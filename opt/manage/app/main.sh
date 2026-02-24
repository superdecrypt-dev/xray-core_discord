main() {
  need_root
  init_runtime_dirs
  ensure_account_quota_dirs
  quota_migrate_dates_to_dateonly
  account_info_compat_refresh_if_needed || true
  main_menu
}
