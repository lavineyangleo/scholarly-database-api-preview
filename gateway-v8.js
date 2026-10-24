/* The decryption key is supplied only in the URL fragment, never to the server. */
"use strict";
(async () => {
  const status = document.getElementById("status");
  const detail = document.getElementById("detail");
  const fail = (title, text) => { status.textContent = title; detail.textContent = text; };
  const encoded = new URLSearchParams(location.hash.slice(1)).get("k");
  if (!encoded || !/^[A-Za-z0-9_-]{43}$/.test(encoded)) {
    fail("需要完整分享链接", "此地址未包含有效访问凭证，请使用分享者提供的完整链接。");
    return;
  }
  if (!globalThis.crypto?.subtle) {
    fail("需要安全连接", "请通过 HTTPS 或本机 localhost 打开预览。");
    return;
  }
  status.textContent = "正在解密报告";
  try {
    const raw = Uint8Array.from(atob(encoded.replace(/-/g,"+").replace(/_/g,"/") + "="), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
    raw.fill(0);
    const response = await fetch("payload.bin", {credentials:"omit", cache:"no-store", referrerPolicy:"no-referrer"});
    if (!response.ok) throw new Error("payload unavailable");
    const payload = new Uint8Array(await response.arrayBuffer());
    const header = new TextEncoder().encode("SDRPREVIEW2\n");
    if (!header.every((v,i) => payload[i] === v)) throw new Error("unsupported format");
    const plaintext = await crypto.subtle.decrypt({name:"AES-GCM", iv:payload.slice(header.length,header.length+12), additionalData:header, tagLength:128}, key, payload.slice(header.length+12));
    const frame = document.getElementById("report");
    frame.srcdoc = new TextDecoder("utf-8", {fatal:true}).decode(plaintext);
    frame.hidden = false;
    document.getElementById("gate").hidden = true;
    document.title = "科技文献数据库 · 评测报告";
  } catch (_) {
    fail("无法打开报告", "分享链接无效、报告文件不可用或内容校验未通过，请向分享者确认最新链接。");
  }
})();
