import { api } from "../api.js";
import { clear, h, pill, table } from "../dom.js";
import { toast } from "../drawer.js";
import { state } from "../state.js";

const ROLES = ["admin", "investigator", "reviewer", "auditor"];

function input(label, attrs) {
  const node = h("input", { ...attrs, "aria-label": label, placeholder: label });
  return node;
}

export async function renderAdmin(root) {
  root.append(h("h1", { text: "Administration" }));
  if (!state.user || state.user.role !== "admin") {
    root.append(h("div", { class: "empty", text: "Only administrators can manage users and case access." }));
    return;
  }
  const usersBox = h("div", { class: "card" });
  const accessBox = h("div", { class: "card", style: { marginTop: "16px" } });
  root.append(
    h("p", {
      class: "lead",
      text: "Accounts, roles and case access. Access is denied by default: a user sees a case only after an administrator grants it. Every change is written to the system ledger.",
    }),
    usersBox,
    accessBox,
  );
  const drawUsers = async () => {
    const users = await api.users();
    clear(usersBox);
    const username = input("Username", { type: "text", maxlength: 40 });
    const name = input("Display name", { type: "text", maxlength: 80 });
    const password = input("Temporary password (12+ characters)", {
      type: "password",
      maxlength: 256,
      autocomplete: "new-password",
    });
    const role = h(
      "select",
      { "aria-label": "Role" },
      ROLES.map((r) => h("option", { value: r, text: r })),
    );
    role.value = "investigator";
    const status = h("span", { class: "faint" });
    const create = h("button", {
      class: "btn",
      type: "button",
      text: "Create user",
      onclick: async () => {
        try {
          await api.createUser({
            username: username.value.trim(),
            password: password.value,
            role: role.value,
            display_name: name.value.trim() || null,
          });
          password.value = "";
          toast("User created");
          await drawUsers();
          await drawAccess();
        } catch (error) {
          status.textContent = error.message;
        }
      },
    });
    usersBox.append(
      h("h2", { text: "Users" }),
      table(
        [
          { label: "Username", render: (u) => h("strong", { text: u.username }) },
          { label: "Name", key: "display_name" },
          {
            label: "Role",
            render: (u) => {
              const pick = h(
                "select",
                { "aria-label": `Role of ${u.username}` },
                ROLES.map((r) => h("option", { value: r, text: r })),
              );
              pick.value = u.role;
              pick.disabled = u.id === state.user.id;
              pick.addEventListener("change", async () => {
                try {
                  await api.updateUser(u.id, { role: pick.value });
                  toast("Role changed");
                } catch (error) {
                  toast(error.message);
                  pick.value = u.role;
                }
              });
              return pick;
            },
          },
          { label: "State", render: (u) => (u.disabled ? pill("disabled", "bad") : pill("active", "good")) },
          {
            label: "",
            render: (u) =>
              u.id === state.user.id
                ? h("span", { class: "faint", text: "you" })
                : h(
                    "div",
                    { class: "row" },
                    h("button", {
                      class: "btn light small",
                      type: "button",
                      text: u.disabled ? "Enable" : "Disable",
                      onclick: async () => {
                        await api.updateUser(u.id, { disabled: !u.disabled });
                        await drawUsers();
                      },
                    }),
                    h("button", {
                      class: "btn light small",
                      type: "button",
                      text: "Sign out everywhere",
                      onclick: async () => {
                        const result = await api.revokeSessions(u.id);
                        toast(`${result.revoked} sessions ended`);
                      },
                    }),
                  ),
          },
        ],
        users,
      ),
      h("h3", { text: "New user" }),
      h("div", { class: "row wrap" }, username, name, password, role, create),
      status,
    );
  };
  const drawAccess = async (caseId) => {
    clear(accessBox);
    const cases = Array.from(document.querySelectorAll("#case-select option")).map((o) => o.value);
    const chosen = caseId || state.caseId || cases[0];
    const pick = h(
      "select",
      { "aria-label": "Case" },
      cases.map((c) => h("option", { value: c, text: c })),
    );
    if (chosen) pick.value = chosen;
    pick.addEventListener("change", () => drawAccess(pick.value));
    accessBox.append(h("h2", { text: "Case access" }), h("div", { class: "row" }, h("span", { text: "Case" }), pick));
    if (!chosen) return;
    const [grants, users] = await Promise.all([api.access(chosen), api.users()]);
    const who = h(
      "select",
      { "aria-label": "User" },
      users
        .filter((u) => u.role !== "admin" && !grants.some((g) => g.id === u.id))
        .map((u) => h("option", { value: String(u.id), text: `${u.username} (${u.role})` })),
    );
    accessBox.append(
      grants.length
        ? table(
            [
              { label: "User", key: "username" },
              { label: "Role", key: "role" },
              {
                label: "",
                render: (g) =>
                  h("button", {
                    class: "btn light small",
                    type: "button",
                    text: "Remove access",
                    onclick: async () => {
                      await api.revokeAccess(chosen, g.id);
                      await drawAccess(chosen);
                    },
                  }),
              },
            ],
            grants,
          )
        : h("p", { class: "faint", text: "Only administrators can open this case." }),
      who.options.length
        ? h(
            "div",
            { class: "row", style: { marginTop: "10px" } },
            who,
            h("button", {
              class: "btn",
              type: "button",
              text: "Grant access",
              onclick: async () => {
                await api.grant(chosen, Number(who.value));
                toast("Access granted and logged");
                await drawAccess(chosen);
              },
            }),
          )
        : null,
    );
  };
  await drawUsers();
  await drawAccess();
}
