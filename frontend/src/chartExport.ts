function safeFilename(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "chart";
}

export async function exportSvgAsPng(
  svg: SVGSVGElement | null,
  name: string,
  background = "#ffffff"
) {
  if (!svg) throw new Error("Chart is not ready for export");
  const viewBox = svg.viewBox.baseVal;
  const width = Math.max(1, viewBox.width || svg.clientWidth);
  const height = Math.max(1, viewBox.height || svg.clientHeight);
  const clone = svg.cloneNode(true) as SVGSVGElement;
  clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  clone.setAttribute("width", String(width));
  clone.setAttribute("height", String(height));

  const source = new XMLSerializer().serializeToString(clone);
  const blob = new Blob([source], { type: "image/svg+xml;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  try {
    const image = new Image();
    image.decoding = "async";
    await new Promise<void>((resolve, reject) => {
      image.onload = () => resolve();
      image.onerror = () => reject(new Error("Browser could not render the chart export"));
      image.src = url;
    });
    const scale = 2;
    const canvas = document.createElement("canvas");
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Canvas export is unavailable in this browser");
    context.scale(scale, scale);
    context.fillStyle = background;
    context.fillRect(0, 0, width, height);
    context.drawImage(image, 0, 0, width, height);
    const png = await new Promise<Blob>((resolve, reject) => {
      canvas.toBlob((result) => result ? resolve(result) : reject(new Error("PNG export failed")), "image/png");
    });
    const downloadUrl = URL.createObjectURL(png);
    const anchor = document.createElement("a");
    anchor.href = downloadUrl;
    anchor.download = `${safeFilename(name)}-${new Date().toISOString().slice(0, 10)}.png`;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
  } finally {
    URL.revokeObjectURL(url);
  }
}
