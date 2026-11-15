const $ = id => document.getElementById(id);
const TEXT = {
  safe: ["Looks safe", "No phishing signs found in this address."],
  suspicious: ["Be careful", "Some signs of phishing. Don't enter passwords or payment details."],
  phishing: ["Likely phishing", "Don't open this link or enter any details."],
};

function showAnatomy(r) {
  // Highlight the part of the address that decides who owns the site.
  const el = $("anatomy"), url = r.url;
  const i = url.toLowerCase().indexOf(r.domain.toLowerCase());
  el.textContent = "";
  if (i < 0) { el.textContent = url; return; }
  const b = document.createElement("b");
  b.textContent = url.slice(i, i + r.domain.length);
  el.append(url.slice(0, i), b, url.slice(i + r.domain.length));
  $("hint").textContent = `The highlighted part, ${r.domain}, is who really owns this site.`;
}

function render(r) {
  const [title, note] = TEXT[r.verdict];
  $("result").dataset.v = r.verdict;
  $("verdict").textContent = title;
  showAnatomy(r);
  $("needle").style.left = "0%";
  requestAnimationFrame(() => requestAnimationFrame(() => $("needle").style.left = Math.min(r.score * 100, 99) + "%"));
  const ul = $("reasons"); ul.textContent = "";
  (r.reasons.length ? r.reasons : [note]).forEach(t => { const li = document.createElement("li"); li.textContent = t; ul.append(li); });
  $("result").hidden = false;
}

async function check(url) {
  $("error").hidden = true; $("go").disabled = true;
  try {
    const res = await fetch("/api/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Something went wrong.");
    render(data);
  } catch (e) {
    $("result").hidden = true; $("error").textContent = e.message; $("error").hidden = false;
  } finally { $("go").disabled = false; }
}

$("form").addEventListener("submit", e => { e.preventDefault(); check($("url").value); });
document.querySelectorAll(".examples button").forEach(b => b.onclick = () => { $("url").value = b.dataset.u; check(b.dataset.u); });
