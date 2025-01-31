import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

export class SignUpDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  @Matches(/^(?=.*[A-Z]).*$/, {
    message: 'Password must contain at least one uppercase letter',
  })
  @Matches(/^(?=.*\d).*$/, {
    message: 'Password must contain at least one number',
  })
  @Matches(/^(?=.*[@$!%*?&]).*$/, {
    message: 'Password must contain at least one special character',
  })
  password: string;
}
