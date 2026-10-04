//! O20: rust-dns as a Windows service (the `windows-service` crate, pure
//! Rust over windows-sys).
//!
//! `rust-dns --install-service --config C:\rust-dns\rust-dns.toml` (in an
//! elevated prompt) registers the service `rust-dns` (automatic start,
//! LocalSystem) whose command line is `rust-dns --windows-service --config
//! <that file, absolute>`; `sc start rust-dns` / `Start-Service rust-dns`
//! starts it, `Stop-Service` stops it as Ctrl-C does, and
//! `rust-dns --uninstall-service` removes it. A service has no console:
//! set `[logging] file` in the config to keep its log. The working
//! directory is the config file's directory, so relative paths in the
//! config (the database) resolve as they do when started from there.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

/// The service's name (and the name `sc` and `Start-Service` use).
pub const NAME: &str = "rust-dns";

define_windows_service!(ffi_service_main, service_main);

/// Hand the process to the service control manager; returns when the
/// service has stopped.
pub fn run_dispatcher() -> anyhow::Result<()> {
    service_dispatcher::start(NAME, ffi_service_main)
        .map_err(|e| anyhow::anyhow!("not started by the service control manager: {e}"))
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("rust-dns service: {e:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    let handler = |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            crate::SHUTDOWN.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(NAME, handler)?;
    let set = |state: ServiceState, code: u32| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
    };
    // The process arguments are the service's launch arguments.
    let cli = <crate::Cli as clap::Parser>::parse();
    if let Some(dir) = cli.config.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::env::set_current_dir(dir)?;
    }
    set(ServiceState::Running, 0)?;
    let result = crate::run(cli);
    set(ServiceState::Stopped, if result.is_ok() { 0 } else { 1 })?;
    result
}

/// Register the service to run with `config` (made absolute).
pub fn install(config: &Path) -> anyhow::Result<()> {
    let config = std::path::absolute(config)?;
    if !config.is_file() {
        anyhow::bail!(
            "{} does not exist; create it first (rust-dns --init-config {})",
            config.display(),
            config.display()
        );
    }
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "rust-dns DNS server".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![
            "--windows-service".into(),
            "--config".into(),
            config.clone().into_os_string(),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
    service
        .set_description("SQLite-backed authoritative DNS server with a web console (rust-dns)")?;
    println!(
        "service '{NAME}' installed (automatic start) with {}; start it with: sc start {NAME}",
        config.display()
    );
    Ok(())
}

/// Stop the service if it runs, and remove it.
pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    service.delete()?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while service.query_status()?.current_state != ServiceState::Stopped {
            if std::time::Instant::now() > deadline {
                anyhow::bail!(
                    "service '{NAME}' did not stop within 30 s; it is removed once it does"
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    println!("service '{NAME}' removed");
    Ok(())
}
