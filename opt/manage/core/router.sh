#!/usr/bin/env bash
# shellcheck shell=bash

manage_router_dispatch() {
  local action="${1:-}"
  case "${action}" in
    "")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}
