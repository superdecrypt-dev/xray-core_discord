export type ButtonTone = "primary" | "secondary" | "success" | "danger";
export type ActionMode = "direct" | "modal";

export interface ModalFieldDef {
  id: string;
  label: string;
  style: "short" | "paragraph";
  required: boolean;
  placeholder?: string;
}

export interface ModalDef {
  title: string;
  fields: ModalFieldDef[];
}

export interface MenuActionDef {
  id: string;
  label: string;
  mode: ActionMode;
  style?: ButtonTone;
  confirm?: boolean;
  modal?: ModalDef;
}

export interface MenuDefinition {
  id: string;
  label: string;
  description: string;
  actions: MenuActionDef[];
}
