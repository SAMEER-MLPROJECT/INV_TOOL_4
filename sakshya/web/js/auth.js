import { api, setCsrf } from "./api.js";
import { clear, h } from "./dom.js";

const screen = document.getElementById("auth-screen");
const card = document.getElementById("auth-card");

function field(label, attrs) {
  const input = h("input", { ...attrs, "aria-label": label });
  return { input, node: h("label", { class: "field" }, h("span", { text: label }), input) };
}

function show(...children) {
  clear(card);
  card.append(
    h(
      "div",
      { class: "auth-brand" },
      h("span", { class: "logo", text: "S" }),
      h(
        "div",
        null,
        h("div", { class: "brand-name", text: "Sakshya" }),
        h("div", { class: "brand-sub", text: "Evidence correlation and crime reconstruction" }),
      ),
    ),
    ...children,
  );
  screen.hidden = false;
}

export function hideAuth() {
  screen.hidden = true;
  clear(card);
}

export function requireLogin(state) {
  return new Promise((resolve) => {
    if (state.demo_open) {
      enterDemo(resolve);
      return;
    }
    if (!state.bootstrapped) {
      showBootstrap(state, resolve);
      return;
    }
    showLogin(resolve);
  });
}

async function enterDemo(resolve) {
  try {
    const result = await api.demo();
    setCsrf(result.csrf);
    hideAuth();
    resolve(result.user);
  } catch (error) {
    showLogin(resolve, `Demo access is unavailable: ${error.message}`);
  }
}

function showLogin(resolve, notice) {
  const username = field("Username", { type: "text", autocomplete: "username", maxlength: 40, required: true });
  const password = field("Password", { type: "password", autocomplete: "current-password", maxlength: 256, required: true });
  const status = h("div", { class: "auth-status", role: "alert", text: notice || "" });
  const submit = h("button", { class: "btn", type: "submit", text: "Sign in" });
  const form = h("form", { class: "auth-form" }, h("h2", { text: "Sign in" }), username.node, password.node, submit, status);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    status.textContent = "Checking";
    try {
      const result = await api.login(username.input.value.trim(), password.input.value);
      setCsrf(result.csrf);
      password.input.value = "";
      hideAuth();
      resolve(result.user);
    } catch (error) {
      status.textContent = error.message;
    } finally {
      submit.disabled = false;
    }
  });
  show(
    form,
    h("p", {
      class: "faint",
      text: "Access is restricted to authorised investigators. Every sign-in and case access is recorded.",
    }),
  );
  username.input.focus();
}

function showBootstrap(state, resolve) {
  if (!state.bootstrap_enabled) {
    show(
      h("h2", { text: "No administrator yet" }),
      h("p", { text: "Create the first administrator on the server with:" }),
      h("div", { class: "raw", text: "python -m sakshya create-admin --username <name>" }),
      h("p", {
        class: "faint",
        text: "Or start the service once with SAKSHYA_BOOTSTRAP_TOKEN set and enter that token here. Reload this page afterwards.",
      }),
    );
    return;
  }
  const token = field("Bootstrap token", { type: "password", autocomplete: "off", maxlength: 200 });
  const username = field("Administrator username", { type: "text", autocomplete: "username", maxlength: 40 });
  const name = field("Display name", { type: "text", maxlength: 80 });
  const password = field("Password (12 characters or more)", { type: "password", autocomplete: "new-password", maxlength: 256 });
  const status = h("div", { class: "auth-status", role: "alert" });
  const submit = h("button", { class: "btn", type: "submit", text: "Create administrator" });
  const form = h(
    "form",
    { class: "auth-form" },
    h("h2", { text: "Create the first administrator" }),
    token.node,
    username.node,
    name.node,
    password.node,
    submit,
    status,
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    try {
      await api.bootstrap({
        token: token.input.value,
        username: username.input.value.trim(),
        password: password.input.value,
        display_name: name.input.value.trim() || null,
      });
      token.input.value = "";
      showLogin(resolve, "Administrator created. Sign in to continue.");
    } catch (error) {
      status.textContent = error.message;
    } finally {
      submit.disabled = false;
    }
  });
  show(form, h("p", { class: "faint", text: "This form works only once, while no account exists." }));
}
