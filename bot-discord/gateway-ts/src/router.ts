import type { MenuActionDef, MenuDefinition } from "./views/types";
import { menu1 } from "./views/menu_1_status";
import { menu2 } from "./views/menu_2_user";
import { menu3 } from "./views/menu_3_quota";
import { menu4 } from "./views/menu_4_network";
import { menu5 } from "./views/menu_5_domain";
import { menu6 } from "./views/menu_6_speedtest";
import { menu7 } from "./views/menu_7_security";
import { menu8 } from "./views/menu_8_maintenance";

export const MENUS: MenuDefinition[] = [menu1, menu2, menu3, menu4, menu5, menu6, menu7, menu8];

export function findMenu(menuId: string): MenuDefinition | undefined {
  return MENUS.find((m) => m.id === menuId);
}

export function findAction(menuId: string, actionId: string): MenuActionDef | undefined {
  const menu = findMenu(menuId);
  return menu?.actions.find((a) => a.id === actionId);
}
