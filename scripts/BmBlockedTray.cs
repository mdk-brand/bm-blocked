using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("bm-blocked")]
[assembly: System.Reflection.AssemblyDescription("Проверка заблокированных площадок Яндекс Директа")]
[assembly: System.Reflection.AssemblyCompany("Brandmaker")]
[assembly: System.Reflection.AssemblyProduct("bm-blocked")]
[assembly: System.Reflection.AssemblyVersion("1.0.1.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.0.1.0")]

namespace BmBlocked
{
    internal static class Program
    {
        private const string SingleInstanceMutexName = @"Local\BmBlockedSingleInstance";

        [STAThread]
        private static void Main(string[] args)
        {
            if (args.Length >= 4 && args[0] == "--apply-update")
            {
                int parentProcessId;
                int.TryParse(args[3], out parentProcessId);
                UpdateApplier.Apply(args[1], args[2], parentProcessId);
                return;
            }

            CleanupOldUpdaterCopies();
            bool isFirstInstance;

            using (var mutex = new Mutex(true, SingleInstanceMutexName, out isFirstInstance))
            {
                if (!isFirstInstance)
                {
                    if (Environment.GetEnvironmentVariable("BM_BLOCKED_LAUNCHER_NO_BROWSER") != "1")
                    {
                        TrayAppContext.OpenService();
                    }
                    return;
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new TrayAppContext());
                GC.KeepAlive(mutex);
            }
        }

        internal static string QuoteArgument(string value)
        {
            return "\"" + (value ?? "").Replace("\"", "\\\"") + "\"";
        }

        private static void CleanupOldUpdaterCopies()
        {
            try
            {
                var currentPath = Path.GetFullPath(Application.ExecutablePath);

                foreach (var file in Directory.GetFiles(Path.GetTempPath(), "bm-blocked-updater-*.exe"))
                {
                    if (!String.Equals(Path.GetFullPath(file), currentPath, StringComparison.OrdinalIgnoreCase))
                    {
                        try { File.Delete(file); } catch { }
                    }
                }
            }
            catch
            {
            }
        }
    }

    internal sealed class ReleaseInfo
    {
        internal string TagName;
        internal Version Version;
        internal string ZipUrl;
        internal string ChecksumUrl;
    }

    internal sealed class PreparedUpdate
    {
        internal ReleaseInfo Release;
        internal string StagingDirectory;
    }

    internal static class UpdateClient
    {
        private const string LatestReleaseApi =
            "https://api.github.com/repos/mdk-brand/bm-blocked/releases/latest";
        private const string ArchiveName = "bm-blocked.zip";
        private const string ChecksumName = "bm-blocked.zip.sha256";

        internal static readonly Version CurrentVersion =
            typeof(UpdateClient).Assembly.GetName().Version;

        internal static ReleaseInfo GetLatestRelease()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            string json;

            using (var client = CreateWebClient())
            {
                json = client.DownloadString(LatestReleaseApi);
            }

            var serializer = new JavaScriptSerializer();
            var payload = serializer.DeserializeObject(json) as Dictionary<string, object>;

            if (payload == null)
            {
                throw new InvalidDataException("GitHub вернул некорректное описание релиза.");
            }

            var tagName = Convert.ToString(payload["tag_name"]);
            var releaseVersion = ParseVersion(tagName);
            var assets = payload["assets"] as object[];
            string zipUrl = null;
            string checksumUrl = null;

            if (assets != null)
            {
                foreach (var item in assets)
                {
                    var asset = item as Dictionary<string, object>;

                    if (asset == null)
                    {
                        continue;
                    }

                    var name = Convert.ToString(asset["name"]);
                    var url = Convert.ToString(asset["browser_download_url"]);

                    if (String.Equals(name, ArchiveName, StringComparison.OrdinalIgnoreCase))
                    {
                        zipUrl = url;
                    }
                    else if (String.Equals(name, ChecksumName, StringComparison.OrdinalIgnoreCase))
                    {
                        checksumUrl = url;
                    }
                }
            }

            if (String.IsNullOrWhiteSpace(zipUrl) || String.IsNullOrWhiteSpace(checksumUrl))
            {
                throw new InvalidDataException(
                    "В последнем релизе отсутствует bm-blocked.zip или файл SHA-256.");
            }

            return new ReleaseInfo
            {
                TagName = tagName,
                Version = releaseVersion,
                ZipUrl = zipUrl,
                ChecksumUrl = checksumUrl
            };
        }

        internal static PreparedUpdate PrepareUpdate(ReleaseInfo release)
        {
            var updatesRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "bm-blocked",
                "updates");
            var updateRoot = Path.Combine(updatesRoot, release.TagName);
            var archivePath = Path.Combine(updateRoot, ArchiveName);
            var checksumPath = Path.Combine(updateRoot, ChecksumName);
            var stagingDirectory = Path.Combine(updateRoot, "staging");

            DeleteDirectoryInside(updatesRoot, updateRoot);
            Directory.CreateDirectory(updateRoot);

            using (var client = CreateWebClient())
            {
                client.DownloadFile(release.ZipUrl, archivePath);
                client.DownloadFile(release.ChecksumUrl, checksumPath);
            }

            VerifyChecksum(archivePath, checksumPath);
            ExtractZipSafely(archivePath, stagingDirectory);
            ValidatePackage(stagingDirectory);

            return new PreparedUpdate
            {
                Release = release,
                StagingDirectory = stagingDirectory
            };
        }

        private static WebClient CreateWebClient()
        {
            var client = new WebClient();
            client.Headers[HttpRequestHeader.UserAgent] =
                "bm-blocked-updater/" + CurrentVersion.ToString(3);
            client.Headers[HttpRequestHeader.Accept] = "application/vnd.github+json";
            return client;
        }

        private static Version ParseVersion(string tagName)
        {
            Version version;
            var normalized = (tagName ?? "").Trim().TrimStart('v', 'V');

            if (!Version.TryParse(normalized, out version))
            {
                throw new InvalidDataException("Некорректная версия релиза: " + tagName);
            }

            return version;
        }

        private static void VerifyChecksum(string archivePath, string checksumPath)
        {
            var checksumText = File.ReadAllText(checksumPath, Encoding.ASCII).Trim();
            var parts = checksumText.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
            var expected = parts.Length > 0 ? parts[0].Trim().ToUpperInvariant() : "";

            if (expected.Length != 64 || !IsHex(expected))
            {
                throw new InvalidDataException("Файл SHA-256 имеет некорректный формат.");
            }

            string actual;

            using (var stream = File.OpenRead(archivePath))
            using (var sha256 = SHA256.Create())
            {
                actual = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "");
            }

            if (!String.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("SHA-256 архива обновления не совпадает.");
            }
        }

        private static bool IsHex(string value)
        {
            foreach (var symbol in value)
            {
                if (!Uri.IsHexDigit(symbol))
                {
                    return false;
                }
            }

            return true;
        }

        private static void ExtractZipSafely(string archivePath, string destinationDirectory)
        {
            Directory.CreateDirectory(destinationDirectory);
            var destinationRoot = Path.GetFullPath(destinationDirectory)
                .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

            using (var archive = ZipFile.OpenRead(archivePath))
            {
                foreach (var entry in archive.Entries)
                {
                    var relativePath = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                    var destinationPath = Path.GetFullPath(
                        Path.Combine(destinationDirectory, relativePath));

                    if (!destinationPath.StartsWith(destinationRoot, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException("В архиве обновления найден опасный путь.");
                    }

                    if (String.IsNullOrEmpty(entry.Name))
                    {
                        Directory.CreateDirectory(destinationPath);
                        continue;
                    }

                    var parentDirectory = Path.GetDirectoryName(destinationPath);

                    if (!String.IsNullOrEmpty(parentDirectory))
                    {
                        Directory.CreateDirectory(parentDirectory);
                    }

                    entry.ExtractToFile(destinationPath, true);
                }
            }
        }

        private static void ValidatePackage(string stagingDirectory)
        {
            var requiredFiles = new[]
            {
                "bm-blocked.exe",
                "server.js",
                "index.html",
                Path.Combine("runtime", "node.exe")
            };

            foreach (var relativePath in requiredFiles)
            {
                if (!File.Exists(Path.Combine(stagingDirectory, relativePath)))
                {
                    throw new InvalidDataException(
                        "В обновлении отсутствует обязательный файл: " + relativePath);
                }
            }
        }

        private static void DeleteDirectoryInside(string parentDirectory, string targetDirectory)
        {
            var parentRoot = Path.GetFullPath(parentDirectory)
                .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var targetPath = Path.GetFullPath(targetDirectory);

            if (!targetPath.StartsWith(parentRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Некорректный путь обновления.");
            }

            if (Directory.Exists(targetPath))
            {
                Directory.Delete(targetPath, true);
            }
        }
    }

    internal static class UpdateApplier
    {
        private const int MoveFileDelayUntilReboot = 0x4;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(
            string existingFileName,
            string newFileName,
            int flags);

        internal static void Apply(string stagingDirectory, string targetDirectory, int parentProcessId)
        {
            try
            {
                WaitForParent(parentProcessId);
                ApplyFiles(stagingDirectory, targetDirectory);

                if (Environment.GetEnvironmentVariable("BM_BLOCKED_UPDATER_NO_RESTART") != "1")
                {
                    var launcherPath = Path.Combine(targetDirectory, "bm-blocked.exe");
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = launcherPath,
                        WorkingDirectory = targetDirectory,
                        UseShellExecute = true
                    });
                }

                TryDeleteUpdateDirectory(stagingDirectory);
                MoveFileEx(Application.ExecutablePath, null, MoveFileDelayUntilReboot);
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "Не удалось установить обновление: " + error.Message,
                    "bm-blocked",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private static void WaitForParent(int parentProcessId)
        {
            if (parentProcessId <= 0)
            {
                return;
            }

            try
            {
                using (var parent = Process.GetProcessById(parentProcessId))
                {
                    parent.WaitForExit(15000);
                }
            }
            catch
            {
            }
        }

        private static void ApplyFiles(string stagingDirectory, string targetDirectory)
        {
            var stagingRoot = Path.GetFullPath(stagingDirectory)
                .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var targetRoot = Path.GetFullPath(targetDirectory)
                .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var updateRoot = Directory.GetParent(
                stagingRoot.TrimEnd(Path.DirectorySeparatorChar));

            if (updateRoot == null)
            {
                throw new InvalidOperationException("Не удалось определить папку обновления.");
            }

            var backupRoot = Path.Combine(
                updateRoot.FullName,
                "backup-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss"));
            var createdFiles = new List<string>();

            if (!Directory.Exists(stagingRoot))
            {
                throw new DirectoryNotFoundException("Папка обновления не найдена.");
            }

            Directory.CreateDirectory(backupRoot);

            try
            {
                foreach (var sourcePath in Directory.GetFiles(stagingRoot, "*", SearchOption.AllDirectories))
                {
                    var relativePath = sourcePath.Substring(stagingRoot.Length);

                    if (String.Equals(relativePath, "auth-config.json", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var targetPath = Path.GetFullPath(Path.Combine(targetRoot, relativePath));

                    if (!targetPath.StartsWith(targetRoot, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException("Некорректный путь файла обновления.");
                    }

                    var targetParent = Path.GetDirectoryName(targetPath);

                    if (!String.IsNullOrEmpty(targetParent))
                    {
                        Directory.CreateDirectory(targetParent);
                    }

                    if (File.Exists(targetPath))
                    {
                        var backupPath = Path.Combine(backupRoot, relativePath);
                        var backupParent = Path.GetDirectoryName(backupPath);

                        if (!String.IsNullOrEmpty(backupParent))
                        {
                            Directory.CreateDirectory(backupParent);
                        }

                        File.Copy(targetPath, backupPath, true);
                    }
                    else
                    {
                        createdFiles.Add(targetPath);
                    }

                    File.Copy(sourcePath, targetPath, true);
                }
            }
            catch
            {
                foreach (var createdFile in createdFiles)
                {
                    try { if (File.Exists(createdFile)) File.Delete(createdFile); } catch { }
                }

                foreach (var backupPath in Directory.GetFiles(backupRoot, "*", SearchOption.AllDirectories))
                {
                    var relativePath = backupPath.Substring(
                        backupRoot.TrimEnd(Path.DirectorySeparatorChar).Length + 1);
                    var targetPath = Path.Combine(targetRoot, relativePath);
                    var targetParent = Path.GetDirectoryName(targetPath);

                    if (!String.IsNullOrEmpty(targetParent))
                    {
                        Directory.CreateDirectory(targetParent);
                    }

                    try { File.Copy(backupPath, targetPath, true); } catch { }
                }

                throw;
            }
        }

        private static void TryDeleteUpdateDirectory(string stagingDirectory)
        {
            try
            {
                var updateRoot = Directory.GetParent(stagingDirectory);

                if (updateRoot != null && updateRoot.Exists)
                {
                    updateRoot.Delete(true);
                }
            }
            catch
            {
            }
        }
    }

    internal sealed class TrayAppContext : ApplicationContext
    {
        private const string Url = "http://127.0.0.1:8124/index.html";
        private readonly NotifyIcon trayIcon;
        private readonly ToolStripMenuItem checkUpdatesItem;
        private readonly ToolStripMenuItem installUpdateItem;
        private readonly Control dispatcher;
        private readonly bool suppressBrowser =
            Environment.GetEnvironmentVariable("BM_BLOCKED_LAUNCHER_NO_BROWSER") == "1";
        private readonly System.Threading.Timer updateTimer;
        private Process serverProcess;
        private PreparedUpdate pendingUpdate;
        private int updateCheckRunning;
        private bool exiting;

        internal TrayAppContext()
        {
            dispatcher = new Control();
            dispatcher.CreateControl();

            checkUpdatesItem = new ToolStripMenuItem("Проверить обновления");
            checkUpdatesItem.Click += delegate { CheckForUpdates(true); };

            installUpdateItem = new ToolStripMenuItem("Обновлений нет");
            installUpdateItem.Enabled = false;
            installUpdateItem.Click += delegate { ConfirmAndApplyUpdate(); };

            trayIcon = new NotifyIcon
            {
                Icon = SystemIcons.Application,
                Text = "bm-blocked",
                Visible = true,
                ContextMenuStrip = BuildMenu()
            };
            trayIcon.DoubleClick += delegate { OpenService(); };
            trayIcon.BalloonTipClicked += delegate { ConfirmAndApplyUpdate(); };

            StartServer();

            if (!suppressBrowser)
            {
                OpenService();
            }

            updateTimer = new System.Threading.Timer(
                delegate { CheckForUpdates(false); },
                null,
                TimeSpan.FromSeconds(5),
                TimeSpan.FromHours(6));
        }

        private ContextMenuStrip BuildMenu()
        {
            var menu = new ContextMenuStrip();
            var versionItem = new ToolStripMenuItem(
                "Версия " + UpdateClient.CurrentVersion.ToString(3));
            versionItem.Enabled = false;
            menu.Items.Add("Открыть", null, delegate { OpenService(); });
            menu.Items.Add("Перезапустить сервер", null, delegate { RestartServer(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(versionItem);
            menu.Items.Add(checkUpdatesItem);
            menu.Items.Add(installUpdateItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Выход", null, delegate { ExitApplication(); });
            return menu;
        }

        private void CheckForUpdates(bool userInitiated)
        {
            if (pendingUpdate != null)
            {
                if (userInitiated)
                {
                    SafeBeginInvoke(delegate { ConfirmAndApplyUpdate(); });
                }
                return;
            }

            if (Interlocked.CompareExchange(ref updateCheckRunning, 1, 0) != 0)
            {
                return;
            }

            SafeBeginInvoke(delegate
            {
                checkUpdatesItem.Enabled = false;
                checkUpdatesItem.Text = "Проверяю обновления...";
                installUpdateItem.Enabled = false;
            });

            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    var release = UpdateClient.GetLatestRelease();

                    if (release.Version <= UpdateClient.CurrentVersion)
                    {
                        SafeBeginInvoke(delegate
                        {
                            ResetUpdateMenu();

                            if (userInitiated)
                            {
                                ShowBalloon("bm-blocked", "Установлена актуальная версия.");
                            }
                        });
                        return;
                    }

                    SafeBeginInvoke(delegate
                    {
                        checkUpdatesItem.Text = "Скачиваю " + release.TagName + "...";
                    });

                    var prepared = UpdateClient.PrepareUpdate(release);

                    SafeBeginInvoke(delegate
                    {
                        pendingUpdate = prepared;
                        checkUpdatesItem.Enabled = true;
                        checkUpdatesItem.Text = "Проверить обновления";
                        installUpdateItem.Enabled = true;
                        installUpdateItem.Text = "Установить " + release.TagName;
                        ShowBalloon(
                            "Обновление готово",
                            release.TagName + " скачано и проверено. Нажмите уведомление для установки.");
                    });
                }
                catch (Exception error)
                {
                    SafeBeginInvoke(delegate
                    {
                        ResetUpdateMenu();

                        if (userInitiated)
                        {
                            MessageBox.Show(
                                "Не удалось проверить обновления: " + error.Message,
                                "bm-blocked",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Error);
                        }
                    });
                }
                finally
                {
                    Interlocked.Exchange(ref updateCheckRunning, 0);
                }
            });
        }

        private void ResetUpdateMenu()
        {
            checkUpdatesItem.Enabled = true;
            checkUpdatesItem.Text = "Проверить обновления";
            installUpdateItem.Enabled = false;
            installUpdateItem.Text = "Обновлений нет";
        }

        private void ConfirmAndApplyUpdate()
        {
            if (pendingUpdate == null || exiting)
            {
                return;
            }

            var answer = MessageBox.Show(
                "Установить " + pendingUpdate.Release.TagName + " сейчас? bm-blocked будет перезапущен.",
                "Обновление bm-blocked",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Information);

            if (answer != DialogResult.Yes)
            {
                return;
            }

            BeginApplyUpdate();
        }

        private void BeginApplyUpdate()
        {
            try
            {
                var updaterPath = Path.Combine(
                    Path.GetTempPath(),
                    "bm-blocked-updater-" + Guid.NewGuid().ToString("N") + ".exe");
                var targetDirectory = AppDomain.CurrentDomain.BaseDirectory;
                var arguments = "--apply-update " +
                    Program.QuoteArgument(pendingUpdate.StagingDirectory) + " " +
                    Program.QuoteArgument(targetDirectory) + " " +
                    Process.GetCurrentProcess().Id;

                File.Copy(Application.ExecutablePath, updaterPath, true);
                StopServer();

                Process.Start(new ProcessStartInfo
                {
                    FileName = updaterPath,
                    Arguments = arguments,
                    WorkingDirectory = Path.GetTempPath(),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });

                ExitApplication(false);
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "Не удалось запустить установку обновления: " + error.Message,
                    "bm-blocked",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void StartServer()
        {
            var appDirectory = AppDomain.CurrentDomain.BaseDirectory;
            var nodePath = Path.Combine(appDirectory, "runtime", "node.exe");
            var serverPath = Path.Combine(appDirectory, "server.js");

            if (!File.Exists(nodePath) || !File.Exists(serverPath))
            {
                MessageBox.Show(
                    "Не найден runtime\\node.exe или server.js рядом с приложением.",
                    "bm-blocked",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            try
            {
                serverProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = nodePath,
                        Arguments = "\"" + serverPath + "\"",
                        WorkingDirectory = appDirectory,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    },
                    EnableRaisingEvents = true
                };

                serverProcess.StartInfo.EnvironmentVariables["BM_BLOCKED_NO_BROWSER"] = "1";
                serverProcess.Start();
                WaitForServer();
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "Не удалось запустить сервер: " + error.Message,
                    "bm-blocked",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void RestartServer()
        {
            StopServer();
            StartServer();
            OpenService();
        }

        private void StopServer()
        {
            try
            {
                if (serverProcess != null && !serverProcess.HasExited)
                {
                    serverProcess.Kill();
                    serverProcess.WaitForExit(3000);
                }
            }
            catch
            {
            }
            finally
            {
                if (serverProcess != null)
                {
                    serverProcess.Dispose();
                    serverProcess = null;
                }
            }
        }

        private static void WaitForServer()
        {
            for (var attempt = 0; attempt < 30; attempt++)
            {
                try
                {
                    var request = (HttpWebRequest)WebRequest.Create(Url);
                    request.Timeout = 500;
                    request.Method = "GET";

                    using (var response = (HttpWebResponse)request.GetResponse())
                    {
                        if ((int)response.StatusCode >= 200 && (int)response.StatusCode < 500)
                        {
                            return;
                        }
                    }
                }
                catch
                {
                    Thread.Sleep(200);
                }
            }
        }

        internal static void OpenService()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = Url,
                    UseShellExecute = true
                });
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "Не удалось открыть страницу: " + error.Message,
                    "bm-blocked",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void ShowBalloon(string title, string text)
        {
            trayIcon.BalloonTipTitle = title;
            trayIcon.BalloonTipText = text;
            trayIcon.ShowBalloonTip(5000);
        }

        private void SafeBeginInvoke(Action action)
        {
            if (exiting || dispatcher.IsDisposed)
            {
                return;
            }

            try { dispatcher.BeginInvoke(action); } catch { }
        }

        private void ExitApplication()
        {
            ExitApplication(true);
        }

        private void ExitApplication(bool stopServer)
        {
            if (exiting)
            {
                return;
            }

            exiting = true;
            updateTimer.Dispose();

            if (stopServer)
            {
                StopServer();
            }

            trayIcon.Visible = false;
            trayIcon.Dispose();
            dispatcher.Dispose();
            ExitThread();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !exiting)
            {
                updateTimer.Dispose();
                trayIcon.Dispose();
                dispatcher.Dispose();
                StopServer();
            }

            base.Dispose(disposing);
        }
    }
}
