export default async function handler(req, res) {
  const backendOrigin =
    process.env.BACKEND_ORIGIN ||
    "https://f6da-122-168-112-31.ngrok-free.app";

  const rawPath = Array.isArray(req.query.path)
    ? req.query.path.join("/")
    : req.query.path || "";

  const query = new URLSearchParams(req.query);
  query.delete("path");

  const targetUrl = new URL(
    `/${rawPath}${query.toString() ? `?${query.toString()}` : ""}`,
    backendOrigin
  );

  const outgoingHeaders = { ...req.headers };
  delete outgoingHeaders.host;
  delete outgoingHeaders["content-length"];
  outgoingHeaders["ngrok-skip-browser-warning"] = "true";

  let body;
  if (!["GET", "HEAD"].includes(req.method || "GET")) {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    }
    if (chunks.length > 0) {
      body = Buffer.concat(chunks);
    }
  }

  const upstream = await fetch(targetUrl, {
    method: req.method,
    headers: outgoingHeaders,
    body,
    redirect: "manual",
  });

  res.status(upstream.status);
  upstream.headers.forEach((value, key) => {
    const k = key.toLowerCase();
    if (k === "transfer-encoding") return;
    if (k === "content-encoding") return;
    res.setHeader(key, value);
  });

  const buffer = Buffer.from(await upstream.arrayBuffer());
  res.send(buffer);
}
