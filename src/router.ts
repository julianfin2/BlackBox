import { createRouter, createWebHashHistory } from "vue-router";
import DesktopApp from "./DesktopApp.vue";

export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", redirect: "/dashboard" },
    {
      path: "/:section(dashboard|incidents|patterns|capabilities|privacy|settings)",
      name: "workspace",
      component: DesktopApp,
    },
    { path: "/:pathMatch(.*)*", redirect: "/dashboard" },
  ],
});
