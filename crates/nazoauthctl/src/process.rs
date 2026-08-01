use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read as _, Write as _},
    path::Path,
    process::{Command, Output, Stdio},
    thread,
    time::Duration,
};

use anyhow::{Context, bail};
use wait_timeout::ChildExt as _;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct Process {
    program: OsString,
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    current_dir: Option<std::path::PathBuf>,
    timeout: Duration,
}

impl Process {
    pub(crate) fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            environment: Vec::new(),
            current_dir: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub(crate) fn arg(mut self, value: impl Into<OsString>) -> Self {
        self.args.push(value.into());
        self
    }

    pub(crate) fn args<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(values.into_iter().map(Into::into));
        self
    }

    pub(crate) fn current_dir(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.current_dir = Some(path.into());
        self
    }

    pub(crate) fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.push((key.into(), value.into()));
        self
    }

    pub(crate) fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        if !test_environment_passthrough() {
            command.env_clear();
            #[cfg(unix)]
            command.env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            );
            #[cfg(unix)]
            command.env("HOME", "/root");
            #[cfg(unix)]
            command.env("LC_ALL", "C");
            #[cfg(windows)]
            for key in ["PATH", "PATHEXT", "SystemRoot", "ComSpec", "TEMP", "TMP"] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
        }
        command.args(&self.args).envs(self.environment.clone());
        if let Some(path) = &self.current_dir {
            command.current_dir(path);
        }
        command
    }

    pub(crate) fn output(&self) -> anyhow::Result<Output> {
        let mut command = self.command();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command
            .spawn()
            .with_context(|| format!("failed to execute {}", self.display_name()))?;
        self.collect_output(child, None)
    }

    pub(crate) fn run_quiet(&self) -> anyhow::Result<()> {
        let output = self.output()?;
        if !output.status.success() {
            bail!(
                "{} failed with status {}",
                self.display_name(),
                output.status
            );
        }
        Ok(())
    }

    pub(crate) fn stdout(&self) -> anyhow::Result<String> {
        let output = self.output()?;
        if !output.status.success() {
            bail!(
                "{} failed with status {}",
                self.display_name(),
                output.status
            );
        }
        String::from_utf8(output.stdout)
            .with_context(|| format!("{} produced non-UTF-8 output", self.display_name()))
    }

    pub(crate) fn stdin_stdout(&self, input: &[u8]) -> anyhow::Result<String> {
        let mut command = self.command();
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(path) = &self.current_dir {
            command.current_dir(path);
        }
        let child = command
            .spawn()
            .with_context(|| format!("failed to execute {}", self.display_name()))?;
        let output = self.collect_output(child, Some(input))?;
        if !output.status.success() {
            bail!(
                "{} failed with status {}",
                self.display_name(),
                output.status
            );
        }
        String::from_utf8(output.stdout)
            .with_context(|| format!("{} produced non-UTF-8 output", self.display_name()))
    }

    /// Returns only a closed classification.  Diagnostic output is deliberately
    /// consumed in-process and is never propagated to the caller, logs, or
    /// audit chain because it may contain deployment details.
    pub(crate) fn stdin_authorization_rejected(&self, input: &[u8]) -> anyhow::Result<bool> {
        let mut command = self.command();
        command
            .stdin(Stdio::piped())
            // `collect_output` drains both pipes to avoid deadlock. The bytes
            // are discarded below and never cross the process boundary.
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(path) = &self.current_dir {
            command.current_dir(path);
        }
        let child = command
            .spawn()
            .with_context(|| format!("failed to execute {}", self.display_name()))?;
        let output = self.collect_output(child, Some(input))?;
        if output.status.success() {
            return Ok(false);
        }
        Ok(String::from_utf8_lossy(&output.stderr)
            .lines()
            .any(|line| line.trim() == "nazoauth-operator-rejection=authorization"))
    }

    pub(crate) fn stdout_file(&self, path: &Path) -> anyhow::Result<()> {
        let file = File::create(path)
            .with_context(|| format!("failed to create command output {}", path.display()))?;
        let mut command = self.command();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(file))
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to execute {}", self.display_name()))?;
        let status = wait_or_kill(&mut child, self.timeout, &self.display_name())?;
        if !status.success() {
            bail!("{} failed with status {status}", self.display_name());
        }
        Ok(())
    }

    pub(crate) fn succeeds(&self) -> bool {
        let mut command = self.command();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(path) = &self.current_dir {
            command.current_dir(path);
        }
        let Ok(mut child) = command.spawn() else {
            return false;
        };
        wait_or_kill(&mut child, self.timeout, &self.display_name())
            .is_ok_and(|status| status.success())
    }

    fn collect_output(
        &self,
        mut child: std::process::Child,
        input: Option<&[u8]>,
    ) -> anyhow::Result<Output> {
        let stdout = child
            .stdout
            .take()
            .context("child stdout was unavailable")?;
        let stderr = child
            .stderr
            .take()
            .context("child stderr was unavailable")?;
        let stdout_reader = thread::spawn(move || read_bounded(stdout));
        let stderr_reader = thread::spawn(move || read_bounded(stderr));
        if let Some(input) = input {
            let mut stdin = child.stdin.take().context("child stdin was unavailable")?;
            if let Err(error) = stdin.write_all(input) {
                child.kill().ok();
                child.wait().ok();
                stdout_reader.join().ok();
                stderr_reader.join().ok();
                return Err(error).context("failed to write bounded child stdin");
            }
        }
        let status = wait_or_kill(&mut child, self.timeout, &self.display_name());
        let stdout = stdout_reader
            .join()
            .map_err(|_| anyhow::anyhow!("child stdout reader failed"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("child stderr reader failed"))??;
        Ok(Output {
            status: status?,
            stdout,
            stderr,
        })
    }

    fn display_name(&self) -> String {
        Path::new(&self.program)
            .file_name()
            .unwrap_or_else(|| OsStr::new("command"))
            .to_string_lossy()
            .into_owned()
    }
}

fn read_bounded(reader: impl std::io::Read) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(MAX_CAPTURE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CAPTURE_BYTES {
        bail!("child output exceeded the capture limit");
    }
    Ok(bytes)
}

fn wait_or_kill(
    child: &mut std::process::Child,
    timeout: Duration,
    display_name: &str,
) -> anyhow::Result<std::process::ExitStatus> {
    if let Some(status) = child.wait_timeout(timeout)? {
        return Ok(status);
    }
    child.kill().ok();
    child.wait().ok();
    bail!(
        "{display_name} timed out after {} seconds",
        timeout.as_secs()
    )
}

fn test_environment_passthrough() -> bool {
    cfg!(debug_assertions) && std::env::var_os("NAZOAUTHCTL_TESTING").is_some()
}

pub(crate) fn command_exists(name: &str) -> bool {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        return candidate.is_file();
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| {
        let direct = directory.join(name);
        if direct.is_file() {
            return true;
        }
        #[cfg(windows)]
        {
            for extension in ["exe", "cmd", "bat"] {
                if directory.join(format!("{name}.{extension}")).is_file() {
                    return true;
                }
            }
        }
        false
    })
}

#[cfg(all(test, unix))]
#[path = "../tests/unit/process.rs"]
mod tests;
