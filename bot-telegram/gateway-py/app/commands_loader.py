from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FieldSpec:
    id: str
    label: str
    required: bool
    placeholder: str


@dataclass(frozen=True)
class ModalSpec:
    title: str
    fields: tuple[FieldSpec, ...]


@dataclass(frozen=True)
class ActionSpec:
    id: str
    label: str
    mode: str
    confirm: bool
    modal: ModalSpec | None


@dataclass(frozen=True)
class MenuSpec:
    id: str
    label: str
    description: str
    actions: tuple[ActionSpec, ...]


class CommandCatalog:
    def __init__(self, menus: list[MenuSpec]) -> None:
        self.menus: tuple[MenuSpec, ...] = tuple(menus)
        self._menu_map = {m.id: m for m in self.menus}

    @classmethod
    def load(cls, commands_file: str) -> "CommandCatalog":
        payload = json.loads(Path(commands_file).read_text(encoding="utf-8"))
        menus: list[MenuSpec] = []
        for raw_menu in payload.get("menus", []):
            menu_id = str(raw_menu.get("id", "")).strip()
            if not menu_id:
                continue

            actions: list[ActionSpec] = []
            for raw_action in raw_menu.get("actions", []):
                action_id = str(raw_action.get("id", "")).strip()
                if not action_id:
                    continue

                modal: ModalSpec | None = None
                raw_modal = raw_action.get("modal")
                if isinstance(raw_modal, dict):
                    fields: list[FieldSpec] = []
                    for raw_field in raw_modal.get("fields", []):
                        field_id = str(raw_field.get("id", "")).strip()
                        if not field_id:
                            continue
                        fields.append(
                            FieldSpec(
                                id=field_id,
                                label=str(raw_field.get("label") or field_id),
                                required=bool(raw_field.get("required", False)),
                                placeholder=str(raw_field.get("placeholder") or "").strip(),
                            )
                        )
                    modal = ModalSpec(
                        title=str(raw_modal.get("title") or "Input"),
                        fields=tuple(fields),
                    )

                actions.append(
                    ActionSpec(
                        id=action_id,
                        label=str(raw_action.get("label") or action_id),
                        mode=str(raw_action.get("mode") or "direct").strip().lower(),
                        confirm=bool(raw_action.get("confirm", False)),
                        modal=modal,
                    )
                )

            menus.append(
                MenuSpec(
                    id=menu_id,
                    label=str(raw_menu.get("label") or f"Menu {menu_id}"),
                    description=str(raw_menu.get("description") or "").strip(),
                    actions=tuple(actions),
                )
            )

        return cls(menus)

    def get_menu(self, menu_id: str) -> MenuSpec | None:
        return self._menu_map.get(menu_id)

    def get_action(self, menu_id: str, action_id: str) -> ActionSpec | None:
        menu = self.get_menu(menu_id)
        if menu is None:
            return None
        for action in menu.actions:
            if action.id == action_id:
                return action
        return None
