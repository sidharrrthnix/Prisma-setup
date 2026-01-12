import type { User as PrismaUser } from '@prisma/client';
export interface User {
  id: string;
  email: string;
  name: string;
  dateOfBirth: string;
  credits: number;
  createdAt: string;
  updatedAt: string;
}

export interface UserWithPassword extends User {
  passwordHash: string;
}

export interface CreateUserParams {
  id?: string;
  email: string;
  passwordHash: string;
  name: string;
  dateOfBirth: string;
  credits?: number;
}

export interface UpdateUserPatch {
  email?: string;
  passwordHash?: string;
  name?: string;
  dateOfBirth?: string;
}

export function toUserDto(user: PrismaUser): User {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    dateOfBirth: user.dateOfBirth.toISOString().split('T')[0],
    role: user.role,
    credits: user.credits,
    createdAt: user.createdAt.toISOString(),
    updatedAt: user.updatedAt.toISOString(),
  };
}

export function toUserWithPasswordDto(
  user: PrismaUser & { passwordHash: string },
): UserWithPassword {
  return {
    ...toUserDto(user),
    passwordHash: user.passwordHash,
  };
}
