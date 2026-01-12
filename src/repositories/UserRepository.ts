import { PrismaClient } from '@prisma/client';
import { mapPrismaError } from '../db/prisma';
import {
  CreateUserParams,
  toUserDto,
  toUserWithPasswordDto,
  UpdateUserPatch,
  User,
  UserWithPassword,
} from './user.types';

export class UserRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async create(params: CreateUserParams): Promise<User> {
    try {
      const user = await this.prisma.user.create({
        data: {
          email: params.email.toLowerCase(),
          passwordHash: params.passwordHash,
          name: params.name,
          dateOfBirth: params.dateOfBirth,
          credits: params.credits ?? 0,
        },
      });
      return toUserDto(user);
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findById(id: string): Promise<User | null> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id },
      });
      return user ? toUserDto(user) : null;
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findByEmail(email: string): Promise<UserWithPassword | null> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { email: email.toLowerCase() },
      });
      return user ? toUserWithPasswordDto(user) : null;
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async findAll(): Promise<User[]> {
    try {
      const users = await this.prisma.user.findMany({
        orderBy: { createdAt: 'desc' },
      });
      return users.map(toUserDto);
    } catch (error) {
      throw mapPrismaError(error);
    }
  }

  async update(id: string, patch: UpdateUserPatch): Promise<User | null> {
    const data: any = {};

    if (patch.email !== undefined) {
      data.email = patch.email.toLowerCase();
    }
    if (patch.passwordHash !== undefined) {
      data.passwordHash = patch.passwordHash;
    }
    if (patch.name !== undefined) {
      data.name = patch.name;
    }
    if (patch.dateOfBirth !== undefined) {
      data.dateOfBirth = patch.dateOfBirth;
    }

    if (Object.keys(data).length === 0) {
      return null;
    }
    try {
      const user = await this.prisma.user.update({
        where: { id },
        data,
      });
      return toUserDto(user);
    } catch (error) {
      throw mapPrismaError(error);
    }
  }
  async delete(id: string): Promise<boolean> {
    try {
      await this.prisma.user.delete({
        where: { id },
      });
      return true;
    } catch (error) {
      throw mapPrismaError(error);
    }
  }
  async list(opts: { limit?: number; offset?: number } = {}): Promise<User[]> {
    const limit = opts.limit ?? 20;
    const offset = opts.offset ?? 0;
    try {
      const users = await this.prisma.user.findMany({
        skip: offset,
        take: limit,
        orderBy: { createdAt: 'desc' },
      });
      return users.map(toUserDto);
    } catch (error) {
      throw mapPrismaError(error);
    }
  }
}
