const BASE = "http://localhost:5000";

async function loadProducts() {
  const res = await fetch(`${BASE}/api/products`);
  return res.json();
}

async function placeOrder(user, item) {
  const res = await fetch("/api/orders", { method: "POST", body: JSON.stringify({ user, item }) });
  return res.json();
}

function renderName(name) {
  document.getElementById("name").innerHTML = name;
}

function checkout() {
  return new Promise((resolve) => setTimeout(() => resolve({ ok: true }), 1500));
}
