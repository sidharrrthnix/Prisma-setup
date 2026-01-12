import z from 'zod';

function calculateAge(birthDate: string) {
  const dob = new Date(birthDate);
  const today = new Date();

  if (Number.isNaN(dob.getDate())) return -1;

  let age = today.getFullYear() - dob.getFullYear();

  const hasBirthdayWent =
    today.getMonth() > dob.getMonth() ||
    (today.getMonth() == dob.getMonth() && today.getDate() >= dob.getDate());

  if (!hasBirthdayWent) age -= 1;
  return age;
}

export const createUserSchema = z
  .object({
    email: z.string().email('Invalid Email'),

    password: z
      .string()
      .min(8)
      .regex(/[A-Z]/, 'Atleast one uppercase')
      .regex(/[a-z]/, 'Atleast one lowercase')
      .regex(/[0-9]/, 'Atleast one number')
      .regex(/[^A-Za-z0-9]/, 'Atleast one special character'),

    name: z.string().trim().min(1).max(100),

    dateOfBirth: z
      .string()
      .refine((value) => !Number.isNaN(new Date(value).getTime()), {
        message: 'DOB must be valid date',
      })
      .refine((value) => calculateAge(value) >= 18, {
        message: 'user must be atleast 18 years old',
      }),
  })
  .strict();

export type CreateUserInput = z.infer<typeof createUserSchema>;

export const updateUserSchema = z
  .object({
    email: z.string().email('Invalid Email').optional(),
    password: z
      .string()
      .min(8)
      .regex(/[A-Z]/, 'Atleast one uppercase')
      .regex(/[a-z]/, 'Atleast one lowercase')
      .regex(/[0-9]/, 'Atleast one number')
      .regex(/[^A-Za-z0-9]/, 'Atleast one special character')
      .optional(),
    name: z.string().trim().min(1).max(100).optional(),
    dateOfBirth: z
      .string()
      .refine((value) => !Number.isNaN(new Date(value).getTime()), {
        message: 'DOB must be valid date',
      })
      .refine((value) => calculateAge(value) >= 18, {
        message: 'user must be atleast 18 years old',
      })
      .optional(),
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0, {
    message: 'At least one field is required',
  });

export type UpdateUserInput = z.infer<typeof updateUserSchema>;

export const transferCreditsSchema = z
  .object({
    fromUserId: z.string().uuid('Invalid User ID'),
    toUserId: z.string().uuid('Invalid User ID'),
    amount: z.number().int().min(1, 'Amount must be a positive integer'),
  })
  .strict()
  .refine((v) => v.fromUserId !== v.toUserId, {
    message: 'From and to user IDs cannot be the same',
  });

export type TransferCreditsInput = z.infer<typeof transferCreditsSchema>;

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(6, 'Password must be at least 6 characters long'),
});
