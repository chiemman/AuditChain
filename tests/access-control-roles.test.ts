 import { describe, it, expect, beforeEach } from "vitest";

 interface RoleData {
		roleId: bigint;
		assignedAt: bigint;
 }

 interface PermissionData {
		allowed: boolean;
 }

 interface RoleDescription {
		description: string;
 }

 const mockContract = {
		admin: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
		paused: false,
		roleCounter: 0n,
		roles: new Map<string, RoleData>(),
		permissions: new Map<string, PermissionData>(),
		roleDescriptions: new Map<string, RoleDescription>(),
		notificationContract: null as string | null,

		isAdmin(caller: string): boolean {
			return caller === this.admin;
		},

		setAdmin(
			caller: string,
			newAdmin: string
		): { value: boolean } | { error: number } {
			if (!this.isAdmin(caller)) return { error: 200 };
			if (newAdmin === "SP000000000000000000002Q6VF78") return { error: 205 };
			this.admin = newAdmin;
			return { value: true };
		},

		setPaused(
			caller: string,
			pause: boolean
		): { value: boolean } | { error: number } {
			if (!this.isAdmin(caller)) return { error: 200 };
			this.paused = pause;
			return { value: true };
		},

		assignRole(
			caller: string,
			user: string,
			roleId: bigint,
			description: string
		): { value: bigint } | { error: number } {
			if (!this.isAdmin(caller)) return { error: 200 };
			if (user === "SP000000000000000000002Q6VF78") return { error: 205 };
			if (roleId > 3n) return { error: 201 };
			if (this.roles.has(user)) return { error: 203 };
			if (this.paused) return { error: 202 };

			const roleCount = this.roleCounter + 1n;
			this.roles.set(user, { roleId, assignedAt: 100n });
			this.roleDescriptions.set(roleId.toString(), { description });
			this.roleCounter = roleCount;
			return { value: roleCount };
		},

		revokeRole(
			caller: string,
			user: string
		): { value: boolean } | { error: number } {
			if (!this.isAdmin(caller)) return { error: 200 };
			if (user === "SP000000000000000000002Q6VF78") return { error: 205 };
			if (!this.roles.has(user)) return { error: 204 };
			if (this.paused) return { error: 202 };

			this.roles.delete(user);
			return { value: true };
		},

		setPermission(
			caller: string,
			roleId: bigint,
			permissionId: bigint,
			allowed: boolean
		): { value: boolean } | { error: number } {
			if (!this.isAdmin(caller)) return { error: 200 };
			if (roleId > 3n) return { error: 201 };
			if (permissionId > 4n) return { error: 201 };
			if (this.paused) return { error: 202 };

			this.permissions.set(`${roleId}:${permissionId}`, { allowed });
			return { value: true };
		},

		getRole(user: string): { value: RoleData } | { error: number } {
			const role = this.roles.get(user);
			if (!role) return { error: 204 };
			return { value: role };
		},

		hasPermission(roleId: bigint, permissionId: bigint): { value: boolean } {
			return {
				value:
					this.permissions.get(`${roleId}:${permissionId}`)?.allowed || false,
			};
		},

		getRoleDescription(
			roleId: bigint
		): { value: RoleDescription } | { error: number } {
			const desc = this.roleDescriptions.get(roleId.toString());
			if (!desc) return { error: 204 };
			return { value: desc };
		},

		getAdmin(): { value: string } {
			return { value: this.admin };
		},

		isPaused(): { value: boolean } {
			return { value: this.paused };
		},

		getRoleCount(): { value: bigint } {
			return { value: this.roleCounter };
		},
 };

 describe("Access Control & Roles", () => {
		const ADMIN = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";
		const COMPANY = "ST2CY5...";
		const AUDITOR = "ST3NB...";
		const DESCRIPTION = "Company role for compliance";

		beforeEach(() => {
			mockContract.admin = ADMIN;
			mockContract.paused = false;
			mockContract.roleCounter = 0n;
			mockContract.roles = new Map();
			mockContract.permissions = new Map();
			mockContract.roleDescriptions = new Map();
			mockContract.notificationContract = null;
		});

		it("should allow admin to assign role", () => {
			const result = mockContract.assignRole(ADMIN, COMPANY, 1n, DESCRIPTION);
			expect(result).toEqual({ value: 1n });
			expect(mockContract.getRole(COMPANY)).toEqual({
				value: { roleId: 1n, assignedAt: 100n },
			});
			expect(mockContract.getRoleDescription(1n)).toEqual({
				value: { description: DESCRIPTION },
			});
		});

		it("should prevent non-admin from assigning role", () => {
			const result = mockContract.assignRole(COMPANY, AUDITOR, 2n, DESCRIPTION);
			expect(result).toEqual({ error: 200 });
		});

		it("should prevent invalid role assignment", () => {
			const result = mockContract.assignRole(ADMIN, COMPANY, 999n, DESCRIPTION);
			expect(result).toEqual({ error: 201 });
		});

		it("should prevent assigning role to already assigned principal", () => {
			mockContract.assignRole(ADMIN, COMPANY, 1n, DESCRIPTION);
			const result = mockContract.assignRole(ADMIN, COMPANY, 2n, DESCRIPTION);
			expect(result).toEqual({ error: 203 });
		});

		it("should prevent assigning role to invalid principal", () => {
			const result = mockContract.assignRole(
				ADMIN,
				"SP000000000000000000002Q6VF78",
				1n,
				DESCRIPTION
			);
			expect(result).toEqual({ error: 205 });
		});

		it("should prevent role assignment when paused", () => {
			mockContract.setPaused(ADMIN, true);
			const result = mockContract.assignRole(ADMIN, COMPANY, 1n, DESCRIPTION);
			expect(result).toEqual({ error: 202 });
		});

		it("should allow admin to revoke role", () => {
			mockContract.assignRole(ADMIN, COMPANY, 1n, DESCRIPTION);
			const result = mockContract.revokeRole(ADMIN, COMPANY);
			expect(result).toEqual({ value: true });
			expect(mockContract.getRole(COMPANY)).toEqual({ error: 204 });
		});

		it("should prevent non-admin from revoking role", () => {
			mockContract.assignRole(ADMIN, COMPANY, 1n, DESCRIPTION);
			const result = mockContract.revokeRole(COMPANY, COMPANY);
			expect(result).toEqual({ error: 200 });
		});

		it("should prevent revoking non-existent role", () => {
			const result = mockContract.revokeRole(ADMIN, COMPANY);
			expect(result).toEqual({ error: 204 });
		});

		it("should allow admin to set permission", () => {
			const result = mockContract.setPermission(ADMIN, 1n, 1n, true);
			expect(result).toEqual({ value: true });
			expect(mockContract.hasPermission(1n, 1n)).toEqual({ value: true });
		});

		it("should prevent non-admin from setting permission", () => {
			const result = mockContract.setPermission(COMPANY, 1n, 1n, true);
			expect(result).toEqual({ error: 200 });
		});

		it("should prevent setting invalid permission", () => {
			const result = mockContract.setPermission(ADMIN, 1n, 999n, true);
			expect(result).toEqual({ error: 201 });
		});

		it("should allow admin to change admin", () => {
			const result = mockContract.setAdmin(ADMIN, AUDITOR);
			expect(result).toEqual({ value: true });
			expect(mockContract.getAdmin()).toEqual({ value: AUDITOR });
		});

		it("should prevent non-admin from changing admin", () => {
			const result = mockContract.setAdmin(COMPANY, AUDITOR);
			expect(result).toEqual({ error: 200 });
		});
 });