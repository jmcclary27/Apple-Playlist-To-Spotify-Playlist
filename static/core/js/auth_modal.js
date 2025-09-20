(function () {
  const uploadBtn   = document.getElementById("uploadBtn");
  const authModal   = document.getElementById("authModal");
  const pendingModal= document.getElementById("pendingModal");
  const closeAuth   = document.getElementById("closeAuth");
  const pendingClose= document.getElementById("pendingClose");
  const tabs        = authModal?.querySelectorAll(".tab");
  const panels      = authModal?.querySelectorAll(".tab-panel");
  const loginForm   = document.getElementById("loginForm");
  const signupForm  = document.getElementById("signupForm");

  function show(el){ el.classList.remove("hidden"); }
  function hide(el){ el.classList.add("hidden"); }

  function switchTab(name) {
    tabs.forEach(t => t.classList.toggle("active", t.dataset.tab === name));
    panels.forEach(p => p.classList.toggle("hidden", p.id !== (name+"Form")));
  }

  tabs?.forEach(tab => tab.addEventListener("click", () => switchTab(tab.dataset.tab)));

  uploadBtn?.addEventListener("click", async (e) => {
    e.preventDefault();
    // ask server if logged in & approved
    const resp = await fetch("/auth/status", { credentials: "same-origin" });
    const data = await resp.json();
    if (!data.authenticated) return show(authModal);
    if (!data.approved)      return show(pendingModal);
    // approved: go to upload page
    window.location.href = "/upload";
  });

  closeAuth?.addEventListener("click", () => hide(authModal));
  pendingClose?.addEventListener("click", () => hide(pendingModal));

  async function submitForm(form, which) {
    const action = form.dataset.action;
    const formData = new FormData(form);
    const errorsDiv = authModal.querySelector(`.form-errors[data-for="${which}"]`);
    errorsDiv.textContent = "";
    const resp = await fetch(action, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-Requested-With": "XMLHttpRequest" },
      body: formData
    });
    const data = await resp.json();
    if (!data.ok) {
      // flatten form errors
      errorsDiv.textContent = Object.values(data.errors).flat().join(" ");
      return;
    }
    hide(authModal);
    if (data.status === "approved") {
      window.location.href = "/upload";
    } else {
      show(pendingModal);
    }
  }

  loginForm?.addEventListener("submit", (e) => { e.preventDefault(); submitForm(loginForm, "login"); });
  signupForm?.addEventListener("submit", (e) => { e.preventDefault(); submitForm(signupForm, "signup"); });
})();
