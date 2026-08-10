$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$source = Join-Path $root "assets\icons\bm-blocked-1024.png"
$output = Join-Path $root "assets\icons"

if (-not (Test-Path -LiteralPath $source)) {
  throw "Icon master not found: $source"
}

Add-Type -AssemblyName System.Drawing

$builderSource = @'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

public static class BmBlockedIconBuilder
{
    private static readonly int[] Sizes = { 16, 24, 32, 48, 64, 128, 256, 512 };

    public static void Build(string sourcePath, string outputDirectory)
    {
        using (var master = new Bitmap(sourcePath))
        {
            if (master.Width != master.Height)
            {
                throw new InvalidDataException("The icon master must be square.");
            }

            var iconPngs = new List<byte[]>();
            var iconSizes = new List<int>();

            foreach (var size in Sizes)
            {
                using (var resized = Resize(master, size))
                {
                    var pngPath = Path.Combine(
                        outputDirectory,
                        "bm-blocked-" + size + ".png");
                    resized.Save(pngPath, ImageFormat.Png);

                    if (size <= 256)
                    {
                        using (var stream = new MemoryStream())
                        {
                            resized.Save(stream, ImageFormat.Png);
                            iconPngs.Add(stream.ToArray());
                            iconSizes.Add(size);
                        }
                    }
                }
            }

            WriteIco(
                Path.Combine(outputDirectory, "bm-blocked.ico"),
                iconSizes,
                iconPngs);
        }
    }

    private static Bitmap Resize(Bitmap source, int size)
    {
        var result = new Bitmap(size, size, PixelFormat.Format32bppArgb);

        using (var graphics = Graphics.FromImage(result))
        {
            graphics.CompositingMode = CompositingMode.SourceCopy;
            graphics.CompositingQuality = CompositingQuality.HighQuality;
            graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
            graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;
            graphics.SmoothingMode = SmoothingMode.HighQuality;
            graphics.DrawImage(source, new Rectangle(0, 0, size, size));
        }

        return result;
    }

    private static void WriteIco(
        string destinationPath,
        IList<int> sizes,
        IList<byte[]> pngs)
    {
        using (var stream = File.Create(destinationPath))
        using (var writer = new BinaryWriter(stream))
        {
            writer.Write((ushort)0);
            writer.Write((ushort)1);
            writer.Write((ushort)pngs.Count);

            var offset = 6 + 16 * pngs.Count;

            for (var index = 0; index < pngs.Count; index++)
            {
                var size = sizes[index];
                writer.Write((byte)(size == 256 ? 0 : size));
                writer.Write((byte)(size == 256 ? 0 : size));
                writer.Write((byte)0);
                writer.Write((byte)0);
                writer.Write((ushort)1);
                writer.Write((ushort)32);
                writer.Write((uint)pngs[index].Length);
                writer.Write((uint)offset);
                offset += pngs[index].Length;
            }

            foreach (var png in pngs)
            {
                writer.Write(png);
            }
        }
    }
}
'@

if (-not ("BmBlockedIconBuilder" -as [type])) {
  Add-Type -TypeDefinition $builderSource -ReferencedAssemblies System.Drawing
}

[BmBlockedIconBuilder]::Build($source, $output)
Copy-Item -Force (Join-Path $output "bm-blocked.ico") (Join-Path $root "favicon.ico")
Copy-Item -Force (Join-Path $output "bm-blocked-32.png") (Join-Path $root "favicon.png")

Write-Host "Icons: $output"
Write-Host "Favicon: $(Join-Path $root 'favicon.ico')"
Write-Host "Favicon PNG: $(Join-Path $root 'favicon.png')"
