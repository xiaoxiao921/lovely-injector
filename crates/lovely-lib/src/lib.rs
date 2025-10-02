#![allow(non_upper_case_globals)]

use core::slice;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fs;
use std::path::{Path, PathBuf};

use crop::Rope;
use itertools::Itertools;
use patch::{Patch, PatchFile, Priority};
use regex_lite::Regex;
use tracing::{error, info, warn};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub mod chunk_vec_cursor;
pub mod patch;

#[cfg(windows)]
mod sys_alloc {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetProcessHeap() -> *mut u8;
        fn HeapAlloc(hHeap: *mut u8, dwFlags: u32, dwBytes: usize) -> *mut u8;
    }

    pub unsafe fn alloc_bytes(len: usize) -> *mut u8 {
        let heap = GetProcessHeap();
        if heap.is_null() {
            return std::ptr::null_mut();
        }

        let mem = HeapAlloc(heap, 0, len);
        mem as *mut u8
    }
}

#[cfg(not(windows))]
mod sys_alloc {
    use super::*;
    extern "C" {
        fn malloc(size: usize) -> *mut c_void;
    }
    pub unsafe fn alloc_bytes(len: usize) -> *mut u8 {
        let mem = malloc(len) as *mut u8;
        mem
    }
}

unsafe fn ptr_to_path(ptr: *const u8) -> &'static Path {
    let cstr = CStr::from_ptr(ptr as _);
    let str_slice = cstr.to_str().expect("Invalid UTF-8 in path");
    Path::new(str_slice)
}

static mut LOG_GUARD: Option<tracing_appender::non_blocking::WorkerGuard> = None;

pub fn log_init(log_file_path: &PathBuf) {
    if log_file_path.is_file() {
        std::fs::remove_file(log_file_path).ok();
    }

    let file = std::fs::File::create(&log_file_path).expect("Failed to create log file");
    let (non_blocking, guard) = tracing_appender::non_blocking(file);

    unsafe { LOG_GUARD = Some(guard) };

    let file_layer = fmt::Layer::default()
        .with_writer(non_blocking)
        .with_timer(fmt::time::LocalTime::rfc_3339())
        .with_level(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false);

    tracing_subscriber::registry().with(file_layer).init();
}

#[no_mangle]
pub unsafe extern "C" fn lovely_init(dir_ptr: *const u8) -> i32 {
    if dir_ptr.is_null() {
        return PatchTableLoadResult::BadDirEntry as i32;
    }

    let dir = ptr_to_path(dir_ptr);

    log_init(
        &dir.parent()
            .expect("Failed to get parent plugins dir")
            .join("lovely.log"),
    );

    info!("lovely lib initializing, mod dir: {:?}", dir);

    match PatchTable::load(&dir) {
        Ok(table) => {
            PATCH_TABLE = table;
            PatchTableLoadResult::Ok as i32
        }
        Err(e) => e as i32,
    }
}

#[repr(i32)]
pub enum ApplyBufferPatchesResultEnum {
    Ok = 0,
    ChunkNameInvalid = 1,
    ModDirNameInvalid = 2,
    ByteBufferInvalid = 3,
    NoFreeNeededUseOriginalBuffer = 4,
    DumpDirCreationFailed = 5,
    DumpFileWriteFailed = 6,
    DumpMetaWriteFailed = 7,
    BufferAllocationFailed = 8,
}

#[repr(C)]
pub struct LovelyApplyBufferPatchesResult {
    pub data_ptr: *mut u8,
    pub data_len: usize,
    pub status: ApplyBufferPatchesResultEnum,
}

/// Apply patches onto the raw buffer.
/// Returns a pointer to a newly allocated patched buffer (owned by the C caller), or null if no patching was necessary.
/// Safety: interacts with raw pointers and external lua state.
#[no_mangle]
pub unsafe extern "C" fn lovely_apply_buffer_patches(
    original_file_content_ptr: *const u8,
    original_file_content_size: usize,
    name_ptr: *const u8,
    plugins_directory_path_ptr: *const u8,
) -> *const LovelyApplyBufferPatchesResult {
    let result = Box::into_raw(Box::new(LovelyApplyBufferPatchesResult {
        data_ptr: original_file_content_ptr as *mut u8,
        data_len: original_file_content_size,
        status: ApplyBufferPatchesResultEnum::Ok,
    }));

    let name = match CStr::from_ptr(name_ptr as _).to_str() {
        Ok(x) => x,
        Err(e) => {
            error!("Failed to convert chunk name to str: {}", e);
            result.as_mut().unwrap().status = ApplyBufferPatchesResultEnum::ChunkNameInvalid;
            return result;
        }
    };

    let name = normalize_target_name(&name);

    let mod_dir = match CStr::from_ptr(plugins_directory_path_ptr as _).to_str() {
        Ok(x) => PathBuf::from(x),
        Err(e) => {
            error!("Failed to convert mod dir path to str: {}", e);
            result.as_mut().unwrap().status = ApplyBufferPatchesResultEnum::ModDirNameInvalid;
            return result;
        }
    };

    // Prepare buffer for patching
    let buf_slice = slice::from_raw_parts(original_file_content_ptr, original_file_content_size);
    let buf_str = match str::from_utf8(buf_slice) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to convert original file content to str: {}", e);
            result.as_mut().unwrap().status = ApplyBufferPatchesResultEnum::ByteBufferInvalid;
            return result;
        }
    };

    // Apply patches onto this buffer
    let patched: String = PATCH_TABLE.apply_patches(&name, buf_str);

    if patched.as_bytes() == buf_slice {
        result.as_mut().unwrap().status =
            ApplyBufferPatchesResultEnum::NoFreeNeededUseOriginalBuffer;
        return result;
    }

    let regex = Regex::new(r#"=\[(\w+)(?: (\w+))? "([^"]+)"\]"#).unwrap();
    let pretty_name = if let Some(capture) = regex.captures(&name) {
        let f1 = capture.get(1).map_or("", |x| x.as_str());
        let f2 = capture.get(2).map_or("", |x| x.as_str());
        let f3 = capture.get(3).map_or("", |x| x.as_str());
        format!("{f1}/{f2}/{f3}")
    } else {
        name.replace("@", "")
    };

    let patch_dump = mod_dir
        .parent()
        .unwrap()
        .join("lovely_dump")
        .join(&pretty_name);

    // Check/writer dump file (protect against path length / wine issue)
    if pretty_name.chars().count() <= 100 && !fs::exists(&patch_dump).unwrap_or(false) {
        if let Some(dump_parent) = patch_dump.parent() {
            if !dump_parent.is_dir() {
                if let Err(e) = fs::create_dir_all(dump_parent) {
                    error!("Failed to create dump directory: {}", e);
                    result.as_mut().unwrap().status =
                        ApplyBufferPatchesResultEnum::DumpDirCreationFailed;
                    return result;
                }
            }
        }

        if let Err(e) = fs::write(&patch_dump, &patched) {
            error!("Failed to write dump file: {}", e);
            result.as_mut().unwrap().status = ApplyBufferPatchesResultEnum::DumpFileWriteFailed;
            return result;
        }

        let mut patch_meta = patch_dump.clone();
        patch_meta.set_extension("txt");
        if let Err(e) = fs::write(&patch_meta, name.replacen("@", "", 1)) {
            error!("Failed to write dump meta file: {}", e);
            result.as_mut().unwrap().status = ApplyBufferPatchesResultEnum::DumpMetaWriteFailed;
            return result;
        }
    }

    // Allocate buffer on system heap
    // patched.len() + 1 and null-terminate because C-strings
    let out_len = patched.len();
    let alloc_size = out_len.checked_add(1).unwrap_or(0);
    if alloc_size == 0 {
        result.as_mut().unwrap().status = ApplyBufferPatchesResultEnum::BufferAllocationFailed;
        return result;
    }

    let dst = sys_alloc::alloc_bytes(alloc_size);
    if dst.is_null() {
        result.as_mut().unwrap().status = ApplyBufferPatchesResultEnum::BufferAllocationFailed;
        return result;
    }

    // copy bytes and null-terminate
    std::ptr::copy_nonoverlapping(patched.as_ptr(), dst, out_len);
    *dst.add(out_len) = 0u8;

    result.as_mut().unwrap().data_ptr = dst;
    result.as_mut().unwrap().data_len = out_len;

    result
}

static mut PATCH_TABLE: PatchTable = PatchTable {
    patches: Vec::new(),
    vars: None,
};

#[repr(i32)]
pub enum PatchTableLoadResult {
    Ok = 0,
    CannotReadModDir = 1,
    BadDirEntry = 2,
    CannotReadLovelyDir = 3,
    StripPrefixFailed = 4,
    MissingParentDir = 5,
    FileReadFailed = 6,
    ParseError = 7,
}

#[derive(Default)]
struct PatchTable {
    // Unsorted
    patches: Vec<(Patch, Priority, PathBuf)>,
    vars: Option<HashMap<String, String>>,
}

fn normalize_target_name(name: &str) -> String {
    if !name.ends_with(".lua") {
        format!("{name}.lua")
    } else {
        name.to_string()
    }
    .to_lowercase()
}

impl PatchTable {
    /// Load patches from the provided mod directory. This scans for lovely patch files
    /// within each subdirectory that matches either:
    /// - MOD_DIR/lovely.toml
    /// - MOD_DIR/lovely/*.toml
    fn load(mod_dir: &Path) -> Result<PatchTable, PatchTableLoadResult> {
        fn filename_cmp(first: &Path, second: &Path) -> Ordering {
            let first = first.file_name().unwrap().to_string_lossy().to_lowercase();
            let second = second.file_name().unwrap().to_string_lossy().to_lowercase();
            first.cmp(&second)
        }

        let mut mod_dirs_vec: Vec<PathBuf> = Vec::new();
        let read_dir = fs::read_dir(mod_dir).map_err(|_| PatchTableLoadResult::CannotReadModDir)?;

        for entry_res in read_dir {
            let entry = entry_res.map_err(|_| PatchTableLoadResult::BadDirEntry)?;
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            match path.file_name() {
                Some(_) => {}
                None => return Err(PatchTableLoadResult::BadDirEntry),
            };

            let ignore_file = path.join(".lovelyignore");
            if ignore_file.is_file() {
                continue;
            }

            mod_dirs_vec.push(path);
        }

        mod_dirs_vec.sort_by(|a, b| filename_cmp(a, b));

        let mod_dirs = mod_dirs_vec.into_iter();

        let mut patch_files: Vec<PathBuf> = Vec::new();

        for dir in mod_dirs {
            let lovely_toml = dir.join("lovely.toml");
            if lovely_toml.is_file() {
                patch_files.push(lovely_toml);
            }

            let lovely_dir = dir.join("lovely");
            if lovely_dir.is_dir() {
                let rd = fs::read_dir(&lovely_dir)
                    .map_err(|_| PatchTableLoadResult::CannotReadLovelyDir)?;

                let mut subfiles: Vec<PathBuf> = rd
                    .filter_map(|entry| entry.ok())
                    .map(|de| de.path())
                    .filter(|p| p.is_file())
                    .filter(|p| {
                        p.extension()
                            .and_then(|ext| ext.to_str())
                            .map(|s| s == "toml")
                            .unwrap_or(false)
                    })
                    .collect();

                subfiles.sort_by(|a, b| filename_cmp(a, b));
                patch_files.extend(subfiles);
            }
        }

        let mut targets: HashSet<String> = HashSet::new();
        let mut patches: Vec<(Patch, Priority, PathBuf)> = Vec::new();
        let mut var_table: HashMap<String, String> = HashMap::new();

        // Load n > 0 patch files from the patch directory, collecting them for later processing.
        for patch_file_path in patch_files {
            let mod_relative_path = match patch_file_path.strip_prefix(mod_dir) {
                Ok(p) => p,
                Err(_) => return Err(PatchTableLoadResult::StripPrefixFailed),
            };

            let patch_dir = match patch_file_path.parent() {
                Some(p) => p,
                None => return Err(PatchTableLoadResult::MissingParentDir),
            };

            // Determine the mod directory from the location of the lovely patch file.
            let mod_dir = if patch_dir.file_name().unwrap() == "lovely" {
                patch_dir.parent().unwrap()
            } else {
                patch_dir
            };

            info!("Loading patch file at {patch_file_path:?} (mod dir: {mod_dir:?})");

            let str = match fs::read_to_string(&patch_file_path) {
                Ok(s) => s,
                Err(_) => return Err(PatchTableLoadResult::FileReadFailed),
            };

            // HACK: Replace instances of {{lovely_hack:patch_dir}} with mod directory.
            let clean_mod_dir = &mod_dir.to_string_lossy().replace("\\", "\\\\");
            let str = str.replace("{{lovely_hack:patch_dir}}", clean_mod_dir);

            // Handle invalid fields in a non-explosive way.
            let ignored_key_callback = |key: serde_ignored::Path| {
                warn!(
                    "Unknown key `{key}` found in patch file at {patch_file_path:?}, ignoring it"
                );
            };

            let mut patch_file: PatchFile = match serde_ignored::deserialize(
                toml::Deserializer::new(&str),
                ignored_key_callback,
            ) {
                Ok(pf) => pf,
                Err(err) => {
                    error!("Failed to parse patch file at {patch_file_path:?}: {err}");
                    continue;
                }
            };

            info!(
                "Loaded patch file at {patch_file_path:?} with {} patches and {} vars",
                patch_file.patches.len(),
                patch_file.vars.len()
            );

            for patch in &mut patch_file.patches[..] {
                match patch {
                    Patch::Copy(ref mut x) => {
                        x.target = normalize_target_name(&x.target);

                        x.sources = x.sources.iter_mut().map(|s| mod_dir.join(s)).collect();
                        targets.insert(x.target.clone());
                        info!("  Copy patch for target '{}'", x.target);
                    }
                    Patch::Pattern(ref mut x) => {
                        x.target = normalize_target_name(&x.target);

                        targets.insert(x.target.clone());
                        info!("  Pattern patch for target '{}'", x.target);
                    }
                    Patch::Regex(ref mut x) => {
                        x.target = normalize_target_name(&x.target);

                        targets.insert(x.target.clone());
                        info!("  Regex patch for target '{}'", x.target);
                    }
                }
            }

            let priority = patch_file.manifest.priority;

            info!(
                "  Priority: {:?}, total patches: {}",
                priority,
                patch_file.patches.len()
            );

            patches.extend(
                patch_file
                    .patches
                    .into_iter()
                    .map(|p| (p, priority, mod_relative_path.to_path_buf())),
            );

            var_table.extend(patch_file.vars);
        }

        Ok(PatchTable {
            vars: Some(var_table),
            patches,
        })
    }

    /// Apply one or more patches onto the target's buffer.
    fn apply_patches(&self, target: &str, buffer: &str) -> String {
        let target = target.strip_prefix('@').unwrap_or(target);

        let copy_patches = self
            .patches
            .iter()
            .filter_map(|(x, prio, path)| match x {
                Patch::Copy(patch) => Some((patch, prio, path)),
                _ => None,
            })
            .sorted_by_key(|(_, &prio, _)| prio)
            .map(|(x, _, path)| (x, path));

        let pattern_and_regex = self
            .patches
            .iter()
            .filter(|(patch, _, _)| matches!(patch, Patch::Pattern(..)))
            .chain(
                self.patches
                    .iter()
                    .filter(|(patch, _, _)| matches!(patch, Patch::Regex(..))),
            )
            .sorted_by_key(|(_, prio, _)| prio)
            .map(|(patch, _, path)| (patch, path))
            .collect_vec();

        // For display + debug use. Incremented every time a patch is applied.
        let mut patch_count = 0;
        let mut rope = Rope::from(buffer);

        // Apply copy patches.
        for (patch, path) in copy_patches {
            if patch.apply(target, &mut rope, path) {
                patch_count += 1;
                info!("Patch applied to '{target}' by mod at path: {:?}", path);
            }
        }

        for (patch, path) in pattern_and_regex {
            let result = match patch {
                Patch::Pattern(x) => x.apply(target, &mut rope, path),
                Patch::Regex(x) => x.apply(target, &mut rope, path),
                _ => unreachable!(),
            };

            if result {
                patch_count += 1;
                info!("Patch applied to '{target}' by mod at path: {:?}", path);
            }
        }

        let mut patched_lines = {
            let inner = rope.to_string();
            inner.split_inclusive('\n').map(String::from).collect_vec()
        };

        // Apply variable interpolation.
        // TODO I don't think it's necessary to split into lines
        // and convert the rope to Strings? seems overcomplicated
        for line in patched_lines.iter_mut() {
            patch::vars::apply_var_interp(line, &self.vars.as_ref().unwrap());
        }

        let patched = patched_lines.concat();

        if patch_count == 1 {
            info!("Applied 1 patch to '{target}'");
        } else {
            info!("Applied {patch_count} patches to '{target}'");
        }

        patched
    }
}
