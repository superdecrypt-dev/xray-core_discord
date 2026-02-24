#!/usr/bin/env bash
# shellcheck shell=bash

manage_ui_hr() {
  local width="${COLUMNS:-80}"
  local line
  if [[ ! "${width}" =~ ^[0-9]+$ || "${width}" -lt 40 ]]; then
    width=80
  fi
  printf -v line '%*s' "${width}" ''
  line="${line// /-}"
  printf '%s\n' "${line}"
}
