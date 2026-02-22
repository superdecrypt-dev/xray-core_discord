export function isAdminRoleAllowed(userRoleIds: string[], adminRoleId?: string): boolean {
  if (!adminRoleId) {
    return true;
  }
  return userRoleIds.includes(adminRoleId);
}
