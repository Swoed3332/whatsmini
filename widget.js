// === AYAR ===
const API_BASE = "https://whatsmini.onrender.com";
// ============

let token = null;
let myUser = null;
let ws = null;

const $ = (id) => document.getElementById(id);

function setAuthStatus(t) { $("authStatus").innerText = t; }
function setKeyStatus(t) { $("keyStatus").innerText = t; }

function showAuth() {
  $("auth").classList.remove("hidden");
  $("chat").classList.add("hidden");
}
function showChat() {
  $("auth").classList.add("hidden");
  $("chat").classList.remove("hidden");
}

function addMsg(text, who) {
  const d = document.createElement("div");
  d.className = "msg " + (who === "me" ? "me" : "them");
  d.innerText = text;
  $("messages").appendChild(d);
  $("messages").scrollTop = $("messages").scrollHeight;
}

function saveSession() {
  if (token && myUser) {
    localStorage.setItem("wm_token", token);
    localStorage.setItem("wm_user", myUser);
  }
}
function loadSession() {
  token = localStorage.getItem("wm_token");
  myUser = localStorage.getItem("wm_user");
}
function clearSession() {
  token = null;
  myUser = null;
  localStorage.removeItem("wm_token");
  localStorage.removeItem("wm_user");
}

async function apiJson(path, method, bodyObj) {
  const res = await fetch(API_BASE + path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: bodyObj ? JSON.stringify(bodyObj) : undefined
  });
  const data = await res.json().catch(() => ({}));
  return { res, data };
}

// ===================== REGISTER =====================
$("btnRegister").onclick = async (e) => {
  e.preventDefault();
  const username = $("username").value.trim();
  const password = $("password").value;

  if (!username || !password) {
    setAuthStatus("username/password boş olamaz");
    return;
  }

  const { res, data } = await apiJson("/api/register", "POST", { username, password });

  if (!res.ok) {
    setAuthStatus("REGISTER ERROR: " + (data.detail || "error"));
    return;
  }

  setAuthStatus("Register OK ✅ Şimdi Login yap.");
};

// ===================== LOGIN =====================
$("btnLogin").onclick = async (e) => {
  e.preventDefault();
  const username = $("username").value.trim();
  const password = $("password").value;

  if (!username || !password) {
    setAuthStatus("username/password boş olamaz");
    return;
  }

  try {
    const { res, data } = await apiJson("/api/login", "POST", { username, password });

    if (!res.ok) {
      setAuthStatus("LOGIN ERROR: " + (data.detail || "error"));
      return;
    }

    token = data.token;
    myUser = data.username;
    saveSession();

    setAuthStatus("Login OK ✅");
    showChat();
    connectWs();

    // login sonrası key upload (login’i bozmaz)
    uploadMyPublicKeySafe();

  } catch (err) {
    setAuthStatus("Network error (backend açık mı?)");
  }
};

// ===================== LOGOUT =====================
$("btnLogout").onclick = (e) => {
  e.preventDefault();
  try { if (ws) ws.close(); } catch {}
  clearSession();
  $("messages").innerHTML = "";
  setAuthStatus("Çıkış yapıldı.");
  showAuth();
};

// ===================== WEBSOCKET =====================
function connectWs() {
  if (!token) return;

  const WS_BASE = API_BASE
  .replace("https://", "wss://")
  .replace("http://", "ws://");

const wsUrl = `${WS_BASE}/ws?token=${encodeURIComponent(token)}`;
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    addMsg("WS bağlandı ✅", "them");
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.text) addMsg(`${msg.from}: ${msg.text}`, "them");
      else addMsg(e.data, "them");
    } catch {
      addMsg(e.data, "them");
    }
  };

  ws.onclose = () => {
    addMsg("WS kapandı ❌ (backend restart olduysa normal)", "them");
  };
}

// ===================== SEND =====================
$("btnSend").onclick = (e) => {
  e.preventDefault();
  const to = $("toUser").value.trim();
  const text = $("msg").value;

  if (!ws || ws.readyState !== 1) {
    addMsg("WS bağlı değil. Login olduktan sonra tekrar dene.", "them");
    return;
  }
  if (!to) {
    addMsg("toUser boş. Kime göndereceğini yaz.", "them");
    return;
  }
  if (!text) return;

  ws.send(JSON.stringify({ to, text }));
  addMsg(`Ben → ${to}: ${text}`, "me");
  $("msg").value = "";
};

// ===================== KEY FETCH (sadece kontrol) =====================
$("btnLoadKey").onclick = async (e) => {
  e.preventDefault();
  const to = $("toUser").value.trim();
  if (!to) { setKeyStatus("toUser boş"); return; }

  try {
    const res = await fetch(API_BASE + "/api/keys/" + encodeURIComponent(to));
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      setKeyStatus("Key yok (404). Karşı taraf login oldu mu?");
      return;
    }
    setKeyStatus("Key var ✅");
  } catch {
    setKeyStatus("Key kontrol hatası (backend?)");
  }
};

// ===================== UPLOAD =====================
$("btnUpload").onclick = async (e) => {
  e.preventDefault();
  if (!token) { addMsg("Önce login ol.", "them"); return; }

  const f = $("file").files[0];
  if (!f) { addMsg("Dosya seç.", "them"); return; }

  const fd = new FormData();
  fd.append("token", token);
  fd.append("file", f);

  try {
    const res = await fetch(API_BASE + "/api/upload", {
      method: "POST",
      body: fd
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      addMsg("Upload error: " + (data.detail || "error"), "them");
      return;
    }

    // ⭐ FULL URL FIX
    const url = API_BASE + data.url;

    // kendi ekranda göster
    addMsg("Dosya: " + url, "me");

    // ⭐ KARŞIYA GÖNDER (senin mesaj sistemine uyumlu)
    const to = $("toUser").value.trim();

    if (!to) {
      addMsg("toUser yazmadan link gönderemezsin.", "them");
      return;
    }

    if (!ws || ws.readyState !== 1) {
      addMsg("WS bağlı değil, link gönderilemedi.", "them");
      return;
    }

    ws.send(JSON.stringify({
      to,
      text: "Dosya: " + url
    }));

  } catch {
    addMsg("Upload network error (backend açık mı?)", "them");
  }
};


// ===================== KEY UPLOAD (login sonrası) =====================
async function uploadMyPublicKeySafe() {
  // Eğer tarayıcı crypto desteklemiyorsa hiç dert değil.
  if (!window.crypto?.subtle) return;

  try {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"]
    );

    const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

    await fetch(API_BASE + "/api/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, public_key_jwk: jwk })
    });
  } catch (e) {
    // Key upload başarısız olsa bile login bozulmasın.
    console.warn("key upload fail", e);
  }
}

// ===================== AUTO-RESTORE SESSION =====================
(function init() {
  loadSession();
  if (token && myUser) {
    showChat();
    connectWs();
    // sayfa yenilense bile key tekrar yüklemeyi dene
    uploadMyPublicKeySafe();
  } else {
    showAuth();
  }
})();