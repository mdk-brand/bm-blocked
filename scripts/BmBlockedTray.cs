using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Toolkit.Uwp.Notifications;

[assembly: System.Reflection.AssemblyTitle("bm-blocked")]
[assembly: System.Reflection.AssemblyDescription("Проверка заблокированных площадок Яндекс Директа")]
[assembly: System.Reflection.AssemblyCompany("Brandmaker")]
[assembly: System.Reflection.AssemblyProduct("bm-blocked")]
[assembly: System.Reflection.AssemblyVersion("1.0.3.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.0.3.0")]

namespace BmBlocked
{
    internal static class Program
    {
        private const string SingleInstanceMutexName = @"Local\BmBlockedSingleInstance";
        private static readonly object ToastActionSync = new object();
        private static Action<string> toastActionHandler;
        private static string pendingToastAction;

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

            InitializeToastActivation();
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

        internal static void SetToastActionHandler(Action<string> handler)
        {
            string pendingAction;

            lock (ToastActionSync)
            {
                toastActionHandler = handler;
                pendingAction = pendingToastAction;
                pendingToastAction = null;
            }

            if (handler != null && !String.IsNullOrWhiteSpace(pendingAction))
            {
                handler(pendingAction);
            }
        }

        private static void InitializeToastActivation()
        {
            try
            {
                ToastNotificationManagerCompat.OnActivated += delegate(
                    ToastNotificationActivatedEventArgsCompat args)
                {
                    string action;

                    try
                    {
                        action = ToastArguments.Parse(args.Argument).Get("action");
                    }
                    catch
                    {
                        action = "";
                    }

                    if (String.IsNullOrWhiteSpace(action))
                    {
                        return;
                    }

                    Action<string> handler;

                    lock (ToastActionSync)
                    {
                        handler = toastActionHandler;

                        if (handler == null)
                        {
                            pendingToastAction = action;
                        }
                    }

                    if (handler != null)
                    {
                        handler(action);
                    }
                };

                ToastNotificationManagerCompat.WasCurrentProcessToastActivated();
            }
            catch
            {
            }
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

                foreach (var directory in Directory.GetDirectories(
                    Path.GetTempPath(),
                    "bm-blocked-updater-*"))
                {
                    if (!currentPath.StartsWith(
                        Path.GetFullPath(directory) + Path.DirectorySeparatorChar,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        try { Directory.Delete(directory, true); } catch { }
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
        internal string Name;
        internal string Notes;
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
                Name = payload.ContainsKey("name") ? Convert.ToString(payload["name"]) : tagName,
                Notes = payload.ContainsKey("body") ? Convert.ToString(payload["body"]) : "",
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
                "Microsoft.Toolkit.Uwp.Notifications.dll",
                "System.ValueTuple.dll",
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
                ScheduleUpdaterCleanup();
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

        private static void ScheduleUpdaterCleanup()
        {
            var executablePath = Path.GetFullPath(Application.ExecutablePath);
            var updaterDirectory = new DirectoryInfo(Path.GetDirectoryName(executablePath));

            if (updaterDirectory.Name.StartsWith(
                "bm-blocked-updater-",
                StringComparison.OrdinalIgnoreCase))
            {
                foreach (var file in updaterDirectory.GetFiles())
                {
                    MoveFileEx(file.FullName, null, MoveFileDelayUntilReboot);
                }

                MoveFileEx(updaterDirectory.FullName, null, MoveFileDelayUntilReboot);
                return;
            }

            MoveFileEx(executablePath, null, MoveFileDelayUntilReboot);
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
        private readonly string notificationPipeName =
            "bm-blocked-notifications-" + Process.GetCurrentProcess().Id;
        private readonly string internalToken = Guid.NewGuid().ToString("N");
        private readonly NotifyIcon trayIcon;
        private readonly ToolStripMenuItem checkUpdatesItem;
        private readonly ToolStripMenuItem installUpdateItem;
        private readonly Control dispatcher;
        private readonly bool suppressBrowser =
            Environment.GetEnvironmentVariable("BM_BLOCKED_LAUNCHER_NO_BROWSER") == "1";
        private readonly System.Threading.Timer updateTimer;
        private readonly Thread notificationThread;
        private readonly object notificationPipeLock = new object();
        private NamedPipeServerStream activeNotificationPipe;
        private Action balloonClickAction;
        private Process serverProcess;
        private ReleaseInfo availableRelease;
        private PreparedUpdate pendingUpdate;
        private string deferredReleaseTag;
        private DateTime deferredUntilUtc;
        private int updateCheckRunning;
        private int updateDownloadRunning;
        private volatile bool notificationListenerStopping;
        private bool exiting;

        internal TrayAppContext()
        {
            dispatcher = new Control();
            dispatcher.CreateControl();
            Program.SetToastActionHandler(HandleUpdateAction);

            checkUpdatesItem = new ToolStripMenuItem("Проверить обновления");
            checkUpdatesItem.Click += delegate { CheckForUpdates(true); };

            installUpdateItem = new ToolStripMenuItem("Обновлений нет");
            installUpdateItem.Enabled = false;
            installUpdateItem.Click += delegate { InstallAvailableUpdate(); };

            trayIcon = new NotifyIcon
            {
                Icon = SystemIcons.Application,
                Text = "bm-blocked",
                Visible = true,
                ContextMenuStrip = BuildMenu()
            };
            trayIcon.DoubleClick += delegate { OpenService(); };
            trayIcon.BalloonTipClicked += delegate
            {
                var action = balloonClickAction;
                balloonClickAction = null;
                if (action != null)
                {
                    action();
                }
            };

            notificationThread = new Thread(ListenForNotifications)
            {
                IsBackground = true,
                Name = "bm-blocked notifications"
            };
            notificationThread.Start();

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
            if (pendingUpdate != null || Interlocked.CompareExchange(ref updateDownloadRunning, 0, 0) != 0)
            {
                if (userInitiated)
                {
                    SafeBeginInvoke(delegate { InstallAvailableUpdate(); });
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
                            availableRelease = null;
                            pendingUpdate = null;
                            ResetUpdateMenu();
                            PublishUpdateState(null, false);

                            if (userInitiated)
                            {
                                ShowBalloon("bm-blocked", "Установлена актуальная версия.");
                            }
                        });
                        return;
                    }

                    SafeBeginInvoke(delegate
                    {
                        availableRelease = release;
                        checkUpdatesItem.Enabled = true;
                        checkUpdatesItem.Text = "Проверить обновления";
                        installUpdateItem.Enabled = true;
                        installUpdateItem.Text = "Установить " + release.TagName;
                        PublishUpdateState(release, false);

                        if (
                            userInitiated ||
                            !String.Equals(
                                deferredReleaseTag,
                                release.TagName,
                                StringComparison.OrdinalIgnoreCase) ||
                            DateTime.UtcNow >= deferredUntilUtc)
                        {
                            ShowUpdateToast(release);
                        }
                    });
                }
                catch (Exception error)
                {
                    SafeBeginInvoke(delegate
                    {
                        if (availableRelease == null)
                        {
                            ResetUpdateMenu();
                        }
                        else
                        {
                            checkUpdatesItem.Enabled = true;
                            checkUpdatesItem.Text = "Проверить обновления";
                            installUpdateItem.Enabled = true;
                            installUpdateItem.Text = "Установить " + availableRelease.TagName;
                        }

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

        private void ShowUpdateToast(ReleaseInfo release)
        {
            if (release == null || exiting)
            {
                return;
            }

            try
            {
                RemoveUpdateToast();

                new ToastContentBuilder()
                    .AddArgument("action", "whats-new")
                    .AddText("Доступна новая версия " + release.TagName)
                    .AddText("Обновление будет скачано только после вашего подтверждения.")
                    .AddButton(new ToastButton()
                        .SetContent("Установить")
                        .AddArgument("action", "install"))
                    .AddButton(new ToastButton()
                        .SetContent("Отложить")
                        .AddArgument("action", "later"))
                    .AddButton(new ToastButton()
                        .SetContent("Что нового?")
                        .AddArgument("action", "whats-new"))
                    .Show();
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "Доступна " + release.TagName +
                    ", но Windows не показала уведомление: " + error.Message,
                    "Обновление bm-blocked",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
        }

        private void HandleUpdateAction(string action)
        {
            SafeBeginInvoke(delegate
            {
                if (String.Equals(action, "install", StringComparison.OrdinalIgnoreCase))
                {
                    InstallAvailableUpdate();
                }
                else if (String.Equals(action, "later", StringComparison.OrdinalIgnoreCase))
                {
                    DeferAvailableUpdate();
                }
                else if (String.Equals(action, "whats-new", StringComparison.OrdinalIgnoreCase))
                {
                    ShowReleaseNotes();
                }
            });
        }

        private void InstallAvailableUpdate()
        {
            if (exiting || Interlocked.CompareExchange(ref updateDownloadRunning, 1, 0) != 0)
            {
                return;
            }

            if (pendingUpdate != null)
            {
                Interlocked.Exchange(ref updateDownloadRunning, 0);
                BeginApplyUpdate();
                return;
            }

            var release = availableRelease;

            if (release == null)
            {
                Interlocked.Exchange(ref updateDownloadRunning, 0);
                CheckForUpdates(true);
                return;
            }

            RemoveUpdateToast();
            PublishUpdateState(release, false);
            checkUpdatesItem.Enabled = false;
            checkUpdatesItem.Text = "Скачиваю " + release.TagName + "...";
            installUpdateItem.Enabled = false;
            installUpdateItem.Text = "Скачивание...";

            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    var prepared = UpdateClient.PrepareUpdate(release);

                    SafeBeginInvoke(delegate
                    {
                        pendingUpdate = prepared;
                        Interlocked.Exchange(ref updateDownloadRunning, 0);
                        BeginApplyUpdate();
                    });
                }
                catch (Exception error)
                {
                    SafeBeginInvoke(delegate
                    {
                        Interlocked.Exchange(ref updateDownloadRunning, 0);
                        checkUpdatesItem.Enabled = true;
                        checkUpdatesItem.Text = "Проверить обновления";
                        installUpdateItem.Enabled = true;
                        installUpdateItem.Text = "Установить " + release.TagName;
                        MessageBox.Show(
                            "Не удалось скачать обновление: " + error.Message,
                            "Обновление bm-blocked",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Error);
                    });
                }
            });
        }

        private void DeferAvailableUpdate()
        {
            if (availableRelease == null)
            {
                return;
            }

            deferredReleaseTag = availableRelease.TagName;
            deferredUntilUtc = DateTime.UtcNow.AddHours(6);
            RemoveUpdateToast();
            PublishUpdateState(availableRelease, false);
        }

        private void ShowReleaseNotes()
        {
            if (availableRelease == null)
            {
                CheckForUpdates(true);
                return;
            }

            RemoveUpdateToast();
            PublishUpdateState(availableRelease, true);
        }

        private void PublishUpdateState(ReleaseInfo release, bool showReleaseNotes)
        {
            var payload = release == null
                ? new Dictionary<string, object>
                {
                    { "action", "clear" }
                }
                : new Dictionary<string, object>
                {
                    { "action", "available" },
                    { "tag", release.TagName },
                    { "name", release.Name },
                    { "notes", release.Notes },
                    { "showReleaseNotes", showReleaseNotes }
                };
            var json = new JavaScriptSerializer().Serialize(payload);

            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    var request = (HttpWebRequest)WebRequest.Create(
                        "http://127.0.0.1:8124/api/internal/update-state");
                    var body = Encoding.UTF8.GetBytes(json);
                    request.Method = "POST";
                    request.ContentType = "application/json; charset=utf-8";
                    request.ContentLength = body.Length;
                    request.Timeout = 2000;
                    request.Headers["X-Bm-Blocked-Internal-Token"] = internalToken;

                    using (var stream = request.GetRequestStream())
                    {
                        stream.Write(body, 0, body.Length);
                    }

                    using (var response = (HttpWebResponse)request.GetResponse())
                    {
                    }
                }
                catch
                {
                }
            });
        }

        private static void RemoveUpdateToast()
        {
            try
            {
                ToastNotificationManagerCompat.History.Clear();
            }
            catch
            {
            }
        }

        private void BeginApplyUpdate()
        {
            try
            {
                var updaterDirectory = Path.Combine(
                    Path.GetTempPath(),
                    "bm-blocked-updater-" + Guid.NewGuid().ToString("N"));
                var updaterPath = Path.Combine(updaterDirectory, "bm-blocked.exe");
                var targetDirectory = AppDomain.CurrentDomain.BaseDirectory;
                var arguments = "--apply-update " +
                    Program.QuoteArgument(pendingUpdate.StagingDirectory) + " " +
                    Program.QuoteArgument(targetDirectory) + " " +
                    Process.GetCurrentProcess().Id;

                Directory.CreateDirectory(updaterDirectory);
                File.Copy(Application.ExecutablePath, updaterPath, true);
                File.Copy(
                    Path.Combine(targetDirectory, "Microsoft.Toolkit.Uwp.Notifications.dll"),
                    Path.Combine(updaterDirectory, "Microsoft.Toolkit.Uwp.Notifications.dll"),
                    true);
                File.Copy(
                    Path.Combine(targetDirectory, "System.ValueTuple.dll"),
                    Path.Combine(updaterDirectory, "System.ValueTuple.dll"),
                    true);
                StopServer();

                Process.Start(new ProcessStartInfo
                {
                    FileName = updaterPath,
                    Arguments = arguments,
                    WorkingDirectory = updaterDirectory,
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
                serverProcess.StartInfo.EnvironmentVariables["BM_BLOCKED_NOTIFICATION_PIPE"] =
                    notificationPipeName;
                serverProcess.StartInfo.EnvironmentVariables["BM_BLOCKED_INTERNAL_TOKEN"] =
                    internalToken;
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
            PublishUpdateState(availableRelease, false);
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

        private void ListenForNotifications()
        {
            while (!notificationListenerStopping)
            {
                try
                {
                    using (var pipe = new NamedPipeServerStream(
                        notificationPipeName,
                        PipeDirection.In,
                        1,
                        PipeTransmissionMode.Byte,
                        PipeOptions.None))
                    {
                        lock (notificationPipeLock)
                        {
                            activeNotificationPipe = pipe;
                        }

                        pipe.WaitForConnection();

                        if (notificationListenerStopping)
                        {
                            return;
                        }

                        string json;
                        using (var reader = new StreamReader(pipe, Encoding.UTF8))
                        {
                            json = reader.ReadToEnd();
                        }

                        var payload = new JavaScriptSerializer().DeserializeObject(json)
                            as Dictionary<string, object>;
                        var type = payload == null
                            ? ""
                            : Convert.ToString(payload.ContainsKey("type") ? payload["type"] : "");
                        var action = payload == null
                            ? ""
                            : Convert.ToString(payload.ContainsKey("action") ? payload["action"] : "");
                        var message = payload == null
                            ? ""
                            : Convert.ToString(payload.ContainsKey("message") ? payload["message"] : "");

                        if (
                            String.Equals(type, "update-action", StringComparison.OrdinalIgnoreCase) &&
                            !String.IsNullOrWhiteSpace(action))
                        {
                            HandleUpdateAction(action);
                        }
                        else if (!String.IsNullOrWhiteSpace(message))
                        {
                            var safeMessage = message.Length > 500 ? message.Substring(0, 500) : message;
                            SafeBeginInvoke(delegate
                            {
                                ShowBalloon("bm-blocked", safeMessage, OpenService);
                            });
                        }
                    }
                }
                catch
                {
                    if (!notificationListenerStopping)
                    {
                        Thread.Sleep(200);
                    }
                }
                finally
                {
                    lock (notificationPipeLock)
                    {
                        activeNotificationPipe = null;
                    }
                }
            }
        }

        private void StopNotificationListener()
        {
            notificationListenerStopping = true;

            lock (notificationPipeLock)
            {
                if (activeNotificationPipe != null)
                {
                    try { activeNotificationPipe.Dispose(); } catch { }
                }
            }

            try { notificationThread.Join(1000); } catch { }
        }

        private void ShowBalloon(string title, string text, Action clickAction = null)
        {
            balloonClickAction = clickAction;
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
            Program.SetToastActionHandler(null);
            updateTimer.Dispose();
            StopNotificationListener();

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
                Program.SetToastActionHandler(null);
                updateTimer.Dispose();
                StopNotificationListener();
                trayIcon.Dispose();
                dispatcher.Dispose();
                StopServer();
            }

            base.Dispose(disposing);
        }
    }
}
