use rustix::fs::statfs;
use rustix::mount::{mount, unmount, MountFlags, UnmountFlags};
use std::ffi::CString;
use std::io;
use std::path::Path;
use tokio::fs;

const TMPFS_MAGIC: u64 = 0x01021994;

pub struct MountManager;

impl MountManager {
    fn mount_tmpfs(target: &Path, size_mb: u32) -> io::Result<()> {
        let data = CString::new(format!("size={}M", size_mb))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        mount(
            "tmpfs",
            target,
            c"tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            Some(data.as_c_str()),
        )
        .map_err(io::Error::from)
    }

    pub fn mount_bind(source: &Path, target: &Path) -> io::Result<()> {
        mount(source, target, c"", MountFlags::BIND, c"")
            .map_err(io::Error::from)
    }

    pub fn unmount_path(target: &Path) -> io::Result<()> {
        unmount(target, UnmountFlags::empty()).map_err(io::Error::from)
    }

    pub fn is_safe_tmpfs(path: &Path) -> io::Result<bool> {
        let stat = statfs(path)?;
        Ok(stat.f_type as u64 == TMPFS_MAGIC)
    }

    pub async fn setup_magisk_env(module_dir: &Path, memory_dirs: &[&Path]) -> io::Result<()> {
        for &dir in memory_dirs {
            if !dir.exists() {
                fs::create_dir_all(dir).await?;
            }

            let needs_mount = if let Some(parent) = dir.parent() {
                !Self::is_safe_tmpfs(parent).unwrap_or(false)
            } else {
                true
            };

            if needs_mount {
                let _ = Self::unmount_path(dir);
                Self::mount_tmpfs(dir, 4)?;
                if !Self::is_safe_tmpfs(dir)? {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("无法验证 tmpfs: {:?}", dir)));
                }
            }
        }

        let real_prop = module_dir.join("module.prop");
        if let Some(&first_mem_dir) = memory_dirs.first() {
            let tmp_prop = first_mem_dir.join("module.prop");

            if real_prop.exists() {
                let content = fs::read_to_string(&real_prop).await?;
                fs::write(&tmp_prop, content).await?;
            } else {
                fs::write(&tmp_prop, crate::prop::PROP_BASE).await?;
            }

            let _ = Self::unmount_path(&real_prop);
            Self::mount_bind(&tmp_prop, &real_prop)?;

            if !Self::is_safe_tmpfs(&real_prop)? {
                let _ = Self::unmount_path(&real_prop);
                return Err(io::Error::new(io::ErrorKind::Other, "无法挂载 module.prop"));
            }
        }
        Ok(())
    }

    pub async fn cleanup_magisk_env(module_dir: &Path) -> io::Result<()> {
        let real_prop = module_dir.join("module.prop");
        let _ = Self::unmount_path(&real_prop);
        let action_sh = module_dir.join("action.sh");
        let _ = Self::unmount_path(&action_sh);
        Ok(())
    }
}
