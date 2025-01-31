import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';

import { SignUpDto } from './dto/sign-up.dto';
import { LoginDto } from './dto/login.dto';
import { InjectModel } from '@nestjs/mongoose';
import mongoose, { Model, Types } from 'mongoose';
import { User } from './schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    private jwtService: JwtService,
  ) {} // inject user model to use it
  async signUp(signUpDto: SignUpDto) {
    const { name, email, password } = signUpDto;
    // TODOs check if the email is in use
    const emailInUse = await this.UserModel.findOne({ email: email });
    if (emailInUse) {
      throw new BadRequestException('Email Already In Use');
    }
    // TODOs hash password - using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);
    // TODOs create user document and save it in mongodb
    await this.UserModel.create({
      name,
      email,
      password: hashedPassword,
    });
    return signUpDto;
  }

  async signIn(loLoginDto: LoginDto) {
    const { email, password } = loLoginDto;
    // TODOs find if user exists by email
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      // throw new NotFoundException('User Not Found');
      throw new UnauthorizedException('Wrong Credentials');
    }
    // TODOs compare entered password with the existing one
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong Credentials');
    }
    // TODOs Generate JWT token
    return this.generateUserTokens(user._id);
  }

  async refreshToken(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOneAndDelete({
      token: refreshToken,
      expiresAt: { $gte: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('Expired Token');
    }
    return this.generateUserTokens(token.userId);
  }

  async generateUserTokens(userId: Types.ObjectId) {
    const accesstoken = this.jwtService.sign({ userId }, { expiresIn: '1h' });
    const refreshToken = uuidv4();

    await this.storeRefreshToken(refreshToken, userId);

    return {
      refreshToken: refreshToken,
      accessToken: accesstoken,
    };
  }
  async storeRefreshToken(token: string, userId: mongoose.Types.ObjectId) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);
    await this.RefreshTokenModel.updateOne(
      {
        token,
        userId,
      },
      { $set: { expiryDate } },
      { upsert: true },
    );
  }
}
