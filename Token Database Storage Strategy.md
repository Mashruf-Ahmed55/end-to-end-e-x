# NestJS Simple Social Login (Google, Facebook, Local) - Complete Implementation

## 1. Dependencies Install

```bash
npm install @nestjs/jwt @nestjs/passport passport passport-jwt passport-local
npm install @nestjs/mongoose mongoose
npm install bcryptjs
npm install class-validator class-transformer
npm install @nestjs/config
npm install passport-google-oauth20 passport-facebook
npm install @types/bcryptjs @types/passport-local @types/passport-google-oauth20 @types/passport-facebook --save-dev
```

## 2. Environment Configuration

```env
# .env
MONGODB_URI="mongodb://localhost:27017/your_database"
JWT_ACCESS_SECRET="your-super-secret-access-key"
JWT_REFRESH_SECRET="your-super-secret-refresh-key"
JWT_ACCESS_EXPIRES_IN="15m"
JWT_REFRESH_EXPIRES_IN="7d"
NODE_ENV="development"

# Google OAuth
GOOGLE_CLIENT_ID="your-google-client-id.googleusercontent.com"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
GOOGLE_CALLBACK_URL="http://localhost:3000/auth/google/callback"

# Facebook OAuth
FACEBOOK_APP_ID="your-facebook-app-id"
FACEBOOK_APP_SECRET="your-facebook-app-secret"
FACEBOOK_CALLBACK_URL="http://localhost:3000/auth/facebook/callback"

# Frontend URLs
FRONTEND_SUCCESS_URL="http://localhost:3001/auth/success"
FRONTEND_FAILURE_URL="http://localhost:3001/auth/failure"
```

## 3. Your Existing User Schema (No Changes Needed)

```typescript
// src/schemas/user.schema.ts (Your existing schema)
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type UserDocument = User & Document;

@Schema({
  timestamps: true,
  collection: 'users',
})
export class User {
  @Prop()
  name?: string;

  @Prop({ required: true, unique: true })
  username: string;

  @Prop({ required: true, unique: true, index: true })
  email: string;

  @Prop({ required: false, select: false })
  password?: string;

  @Prop()
  avatar?: string;

  @Prop()
  avatarId?: string;

  @Prop()
  phone?: string;

  @Prop({
    required: true,
    enum: ['active', 'inactive', 'blocked'],
    default: 'active',
  })
  status: string;

  @Prop({
    required: true,
    enum: ['customer', 'admin', 'super-admin'],
    default: 'customer',
  })
  role: string;

  @Prop({
    required: true,
    enum: ['male', 'female', 'other'],
    default: 'other',
  })
  gender: string;

  @Prop({ required: true, default: false })
  isVerified: boolean;

  @Prop({ type: [Types.ObjectId], ref: 'Address' })
  address: Types.ObjectId[];

  @Prop({
    required: true,
    enum: ['google', 'facebook', 'email & password'],
  })
  userType: string;

  @Prop()
  otp?: string;

  @Prop({ type: Date, default: null })
  otpExpired?: Date;

  @Prop({ default: 0 })
  otpAttempt: number;

  @Prop({ type: Date, default: null })
  otpLastSent?: Date;

  @Prop()
  resetPasswordToken?: string;

  @Prop({ type: Date, default: null })
  resetPasswordTokenExpired?: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
```

## 4. Token Schema (Same as before)

```typescript
// src/schemas/user-token.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type UserTokenDocument = UserToken & Document;

interface DeviceInfo {
  userAgent?: string;
  ip?: string;
  deviceName?: string;
}

@Schema({
  timestamps: true,
  collection: 'user_tokens',
})
export class UserToken {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true })
  userId: Types.ObjectId;

  @Prop({ required: true, unique: true })
  tokenHash: string;

  @Prop({ required: true })
  refreshTokenHash: string;

  @Prop({ type: Object })
  deviceInfo?: DeviceInfo;

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ required: true })
  expiresAt: Date;

  @Prop({ default: Date.now })
  lastUsedAt: Date;

  @Prop({ default: Date.now })
  createdAt: Date;

  @Prop({ default: Date.now })
  updatedAt: Date;
}

export const UserTokenSchema = SchemaFactory.createForClass(UserToken);

// Indexes
UserTokenSchema.index({ tokenHash: 1 });
UserTokenSchema.index({ userId: 1 });
UserTokenSchema.index({ expiresAt: 1 });
UserTokenSchema.index({ isActive: 1 });
```

## 5. DTOs

```typescript
// src/auth/dto/auth.dto.ts
import { IsEmail, IsNotEmpty, IsOptional, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  password: string;

  @IsNotEmpty()
  @IsString()
  username: string;

  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  phone?: string;
}

export class LoginDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}

export class VerifyOtpDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  otp: string;
}
```

## 6. Token Service (Same as before)

```typescript
// src/auth/services/token.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UserToken, UserTokenDocument } from '../../schemas/user-token.schema';
import { User, UserDocument } from '../../schemas/user.schema';
import * as crypto from 'crypto';

interface DeviceInfo {
  userAgent?: string;
  ip?: string;
  deviceName?: string;
}

interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class TokenService {
  constructor(
    @InjectModel(UserToken.name)
    private userTokenModel: Model<UserTokenDocument>,
    @InjectModel(User.name)
    private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async generateTokenPair(
    userId: string,
    deviceInfo: DeviceInfo,
  ): Promise<TokenPair> {
    // Access token generate (JWT)
    const accessToken = this.jwtService.sign(
      {
        userId,
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
      },
      {
        secret: this.configService.get('JWT_ACCESS_SECRET'),
        expiresIn: this.configService.get('JWT_ACCESS_EXPIRES_IN'),
      },
    );

    // Refresh token generate (random string)
    const refreshToken = crypto.randomBytes(32).toString('hex');

    // Hash tokens for database storage
    const tokenHash = this.hashToken(accessToken);
    const refreshTokenHash = this.hashToken(refreshToken);

    // Database e save
    await this.userTokenModel.create({
      userId: new Types.ObjectId(userId),
      tokenHash,
      refreshTokenHash,
      deviceInfo,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      isActive: true,
    });

    return { accessToken, refreshToken };
  }

  async validateAccessToken(token: string): Promise<UserDocument> {
    try {
      // JWT verify
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.get('JWT_ACCESS_SECRET'),
      });

      const tokenHash = this.hashToken(token);

      // Database theke check
      const dbToken = await this.userTokenModel
        .findOne({
          tokenHash,
          userId: decoded.userId,
          isActive: true,
          expiresAt: { $gt: new Date() },
        })
        .populate('userId');

      if (!dbToken) {
        throw new UnauthorizedException('Token not found in database');
      }

      const user = await this.userModel.findById(decoded.userId);
      if (!user || user.status !== 'active') {
        throw new UnauthorizedException('User not found or inactive');
      }

      // Last used time update
      await this.userTokenModel.findByIdAndUpdate(dbToken._id, {
        lastUsedAt: new Date(),
      });

      return user;
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async refreshTokenPair(
    refreshToken: string,
    deviceInfo: DeviceInfo,
  ): Promise<TokenPair> {
    const refreshTokenHash = this.hashToken(refreshToken);

    const dbToken = await this.userTokenModel
      .findOne({
        refreshTokenHash,
        isActive: true,
      })
      .populate('userId');

    if (!dbToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.userModel.findById(dbToken.userId);
    if (!user || user.status !== 'active') {
      throw new UnauthorizedException('User not found or inactive');
    }

    // Purano token deactivate
    await this.userTokenModel.findByIdAndUpdate(dbToken._id, {
      isActive: false,
    });

    // Notun token pair generate
    return this.generateTokenPair(dbToken.userId.toString(), deviceInfo);
  }

  async revokeToken(token: string): Promise<void> {
    const tokenHash = this.hashToken(token);
    await this.userTokenModel.updateMany({ tokenHash }, { isActive: false });
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    await this.userTokenModel.updateMany(
      { userId: new Types.ObjectId(userId), isActive: true },
      { isActive: false },
    );
  }

  async cleanupExpiredTokens(): Promise<number> {
    const result = await this.userTokenModel.deleteMany({
      expiresAt: { $lt: new Date() },
    });
    return result.deletedCount || 0;
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}
```

## 7. Local Strategy (Passport-Local)

```typescript
// src/auth/strategies/local.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email', // Use email instead of username
    });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }
    return user;
  }
}
```

## 8. JWT Strategy

```typescript
// src/auth/strategies/jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { TokenService } from '../services/token.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private tokenService: TokenService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_ACCESS_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(req: any, payload: any) {
    try {
      const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);

      if (!token) {
        throw new UnauthorizedException('Token not found');
      }

      const user = await this.tokenService.validateAccessToken(token);

      if (!user || user.status !== 'active') {
        throw new UnauthorizedException('User not found or inactive');
      }

      return {
        id: user._id,
        email: user.email,
        username: user.username,
        name: user.name,
        role: user.role,
        userType: user.userType,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}
```

## 9. Google Strategy

```typescript
// src/auth/strategies/google.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private configService: ConfigService) {
    super({
      clientID: configService.get('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, name, emails, photos } = profile;

    const user = {
      googleId: id,
      email: emails[0].value,
      name: `${name.givenName} ${name.familyName}`,
      avatar: photos[0].value,
      userType: 'google',
    };

    done(null, user);
  }
}
```

## 10. Facebook Strategy

```typescript
// src/auth/strategies/facebook.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-facebook';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  constructor(private configService: ConfigService) {
    super({
      clientID: configService.get('FACEBOOK_APP_ID'),
      clientSecret: configService.get('FACEBOOK_APP_SECRET'),
      callbackURL: configService.get('FACEBOOK_CALLBACK_URL'),
      scope: 'email',
      profileFields: ['emails', 'name', 'picture.type(large)'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (err: any, user: any, info?: any) => void,
  ): Promise<any> {
    const { id, name, emails, photos } = profile;

    const user = {
      facebookId: id,
      email: emails && emails[0] ? emails[0].value : null,
      name: `${name.givenName} ${name.familyName}`,
      avatar: photos && photos[0] ? photos[0].value : null,
      userType: 'facebook',
    };

    done(null, user);
  }
}
```

## 11. Auth Service (Updated)

```typescript
// src/auth/auth.service.ts
import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../schemas/user.schema';
import { TokenService } from './services/token.service';
import { RegisterDto, LoginDto, VerifyOtpDto } from './dto/auth.dto';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';

interface DeviceInfo {
  userAgent?: string;
  ip?: string;
  deviceName?: string;
}

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private tokenService: TokenService,
  ) {}

  // Local Authentication - Register
  async register(dto: RegisterDto, deviceInfo: DeviceInfo) {
    // Check if user exists
    const existingUser = await this.userModel.findOne({
      $or: [{ email: dto.email }, { username: dto.username }],
    });

    if (existingUser) {
      throw new ConflictException('User already exists with this email or username');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(dto.password, 12);

    // Generate OTP for email verification
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpired = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create user
    const user = await this.userModel.create({
      email: dto.email,
      username: dto.username,
      password: hashedPassword,
      name: dto.name,
      phone: dto.phone,
      userType: 'email & password',
      otp,
      otpExpired,
      otpAttempt: 0,
      otpLastSent: new Date(),
      isVerified: false,
      status: 'inactive', // User will be activated after OTP verification
      role: 'customer',
    });

    // TODO: Send OTP email
    console.log(`OTP for ${dto.email}: ${otp}`);

    return {
      success: true,
      message: 'Registration successful. Please verify your email with OTP.',
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        name: user.name,
      },
    };
  }

  // Verify OTP
  async verifyOtp(dto: VerifyOtpDto, deviceInfo: DeviceInfo) {
    const user = await this.userModel.findOne({ email: dto.email });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (!user.otp || !user.otpExpired) {
      throw new BadRequestException('No OTP found. Please request a new one.');
    }

    if (new Date() > user.otpExpired) {
      throw new BadRequestException('OTP has expired');
    }

    if (user.otpAttempt >= 5) {
      throw new BadRequestException('Too many OTP attempts. Please request a new one.');
    }

    if (user.otp !== dto.otp) {
      await this.userModel.findByIdAndUpdate(user._id, {
        otpAttempt: user.otpAttempt + 1,
      });
      throw new BadRequestException('Invalid OTP');
    }

    // OTP verified - activate user
    await this.userModel.findByIdAndUpdate(user._id, {
      isVerified: true,
      status: 'active',
      otp: undefined,
      otpExpired: undefined,
      otpAttempt: 0,
    });

    // Generate tokens
    const { accessToken, refreshToken } = await this.tokenService.generateTokenPair(
      user._id.toString(),
      deviceInfo,
    );

    return {
      success: true,
      message: 'Email verified successfully',
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        name: user.name,
        userType: user.userType,
      },
      accessToken,
      refreshToken,
    };
  }

  // Resend OTP
  async resendOtp(email: string) {
    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.isVerified) {
      throw new BadRequestException('User is already verified');
    }

    // Check if can send OTP (rate limiting)
    const timeSinceLastSent = user.otpLastSent
      ? new Date().getTime() - user.otpLastSent.getTime()
      : 0;

    if (timeSinceLastSent < 60000) { // 1 minute
      throw new BadRequestException('Please wait before requesting another OTP');
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpired = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await this.userModel.findByIdAndUpdate(user._id, {
      otp,
      otpExpired,
      otpAttempt: 0,
      otpLastSent: new Date(),
    });

    // TODO: Send OTP email
    console.log(`New OTP for ${email}: ${otp}`);

    return {
      success: true,
      message: 'OTP sent successfully',
    };
  }

  // Local Authentication - Login (used by passport-local)
  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userModel.findOne({ email }).select('+password');

    if (!user || user.status !== 'active' || !user.isVerified) {
      return null;
    }

    if (!user.password) {
      throw new UnauthorizedException('Please login with your social account');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return null;
    }

    return {
      id: user._id,
      email: user.email,
      username: user.username,
      name: user.name,
      userType: user.userType,
    };
  }

  // Login with tokens
  async login(user: any, deviceInfo: DeviceInfo) {
    const { accessToken, refreshToken } = await this.tokenService.generateTokenPair(
      user.id.toString(),
      deviceInfo,
    );

    return {
      user,
      accessToken,
      refreshToken,
    };
  }

  // Social Authentication - Google/Facebook
  async socialAuth(socialUser: any, deviceInfo: DeviceInfo) {
    let user = await this.userModel.findOne({ email: socialUser.email });

    if (user) {
      // User exists, check if userType matches
      if (user.userType !== socialUser.userType) {
        // User exists with different auth method
        throw new ConflictException(
          `User exists with ${user.userType} authentication. Please use that method to login.`
        );
      }

      // Update user info if needed
      if (!user.avatar && socialUser.avatar) {
        await this.userModel.findByIdAndUpdate(user._id, {
          avatar: socialUser.avatar,
        });
        user.avatar = socialUser.avatar;
      }
    } else {
      // Create new user for social auth
      const username = this.generateUsernameFromEmail(socialUser.email);

      // Ensure username is unique
      const uniqueUsername = await this.ensureUniqueUsername(username);

      user = await this.userModel.create({
        email: socialUser.email,
        username: uniqueUsername,
        name: socialUser.name,
        avatar: socialUser.avatar,
        userType: socialUser.userType,
        isVerified: true, // Social accounts are auto-verified
        status: 'active',
        role: 'customer',
      });
    }

    // Generate tokens
    const { accessToken, refreshToken } = await this.tokenService.generateTokenPair(
      user._id.toString(),
      deviceInfo,
    );

    return {
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        name: user.name,
        avatar: user.avatar,
        userType: user.userType,
      },
      accessToken,
      refreshToken,
      isNewUser: !user.createdAt || (new Date().getTime() - new Date(user.createdAt).getTime()) < 5000,
    };
  }

  // Helper methods
  private generateUsernameFromEmail(email: string): string {
    return email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  private async ensureUniqueUsername(baseUsername: string): Promise<string> {
    let username = baseUsername;
    let counter = 1;

    while (await this.userModel.findOne({ username })) {
      username = `${baseUsername}${counter}`;
      counter++;
    }

    return username;
  }

  async refreshToken(refreshToken: string, deviceInfo: DeviceInfo) {
    return this.tokenService.refreshTokenPair(refreshToken, deviceInfo);
  }

  async logout(accessToken: string) {
    await this.tokenService.revokeToken(accessToken);
  }

  async logoutAll(userId: string) {
    await this.tokenService.revokeAllUserTokens(userId);
  }

  async getUserProfile(userId: string) {
    return this.userModel.findById(userId).select({ password: 0 });
  }
}
```

## 12. Guards

```typescript
// src/auth/guards/local-auth.guard.ts
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}

// src/auth/guards/jwt-auth.guard.ts
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}

// src/auth/guards/google-auth.guard.ts
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {}

// src/auth/guards/facebook-auth.guard.ts
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class FacebookAuthGuard extends AuthGuard('facebook') {}
```

## 13. Auth Controller

```typescript
// src/auth/auth.controller.ts
import {
  Controller,
  Post,
  Body,
  Req,
  Res,
  UseGuards,
  Get,
  HttpCode,
  HttpStatus,
  Query,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, VerifyOtpDto } from './dto/auth.dto';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { FacebookAuthGuard } from './guards/facebook-auth.guard';
import { GetUser } from './decorators/get-user.decorator';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // Local Registration
  @Post('register')
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
  ) {
    const deviceInfo = {
      userAgent: req.headers['user-agent'],
      ip: req.ip || req.connection.remoteAddress,
    };

    return this.authService.register(dto, deviceInfo);
  }

  // Verify OTP
  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  async verifyOtp(
    @Body() dto: VerifyOtpDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const deviceInfo = {
      userAgent: req.headers['user-agent'],
      ip: req.ip || req.connection.remoteAddress,
    };

    const result = await this.authService.verifyOtp(dto, deviceInfo);

    // Set refresh token in cookie
    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      success: true,
      message: result.message,
      user: result.user,
      accessToken: result.accessToken,
    };
  }

  // Resend OTP
  @Post('resend-otp')
  @HttpCode(HttpStatus.OK)
  async resendOtp(@Body('email') email: string) {
    return this.authService.resendOtp(email);
  }

  // Local Login
  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Req() req: Request & { user: any },
    @Res({ passthrough: true }) res: Response,
  ) {
    const deviceInfo = {
      userAgent: req.headers['user-agent'],
      ip: req.ip || req.connection.remoteAddress,
    };

    const result = await this.authService.login(req.user, deviceInfo);

    // Set refresh token in cookie
    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      success: true,
      message: 'Login successful',
      user: result.user,
      accessToken: result.accessToken,
    };
  }

  // Google OAuth Routes
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth(@Req() req: Request) {
    // Initiates Google OAuth flow
  }

  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthCallback(
    @Req() req: Request & { user: any },
    @Res() res: Response,
  ) {
    try {
      const deviceInfo = {
        userAgent: req.headers['user-agent'],
        ip: req.ip || req.connection.remoteAddress,
      };

      const result = await this.authService.socialAuth(req.user, deviceInfo);

      // Set refresh token in cookie
      this.setRefreshTokenCookie(res, result.refreshToken);

      // Redirect to frontend with success
      const frontendUrl = process.env.FRONTEND_SUCCESS_URL;
      const redirectUrl = new URL(frontendUrl);
      redirectUrl.searchParams.set('token', result.accessToken);
      redirectUrl.searchParams.set('newUser', result.isNewUser.toString());

      res.redirect(redirectUrl.toString());
    } catch (error) {
      const errorUrl = new URL(process.env.FRONTEND_FAILURE_URL);
      errorUrl.searchParams.set('error', error.message);
      res.redirect(errorUrl.toString());
    }
  }

  // Facebook OAuth Routes
  @Get('facebook')
  @UseGuards(FacebookAuthGuard)
  async facebookAuth(@Req() req: Request) {
    // Initiates Facebook OAuth flow
  }

  @Get('facebook/callback')
  @UseGuards(FacebookAuthGuard)
  async facebookAuthCallback(
    @Req() req: Request & { user: any },
    @Res() res: Response,
  ) {
    try {
      const deviceInfo = {
        userAgent: req.headers['user-agent'],
        ip: req.ip || req.connection.remoteAddress,
      };

      const result = await this.authService.socialAuth(req.user, deviceInfo);

      // Set refresh token in cookie
      this.setRefreshTokenCookie(res, result.refreshToken);

      // Redirect to frontend with success
      const frontendUrl = process.env.FRONTEND_SUCCESS_URL;
      const redirectUrl = new URL(frontendUrl);
      redirectUrl.searchParams.set('token', result.accessToken);
      redirectUrl.searchParams.set('newUser', result.isNewUser.toString());

      res.redirect(redirectUrl.toString());
    } catch (error) {
      const errorUrl = new URL(process.env.FRONTEND_FAILURE_URL);
      errorUrl.searchParams.set('error', error.message);
      res.redirect(errorUrl.toString());
    }
  }

  // Refresh Token
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    const deviceInfo = {
      userAgent: req.headers['user-agent'],
      ip: req.ip || req.connection.remoteAddress,
    };

    const result = await this.authService.refreshToken(refreshToken, deviceInfo);

    // Set new refresh token
    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      success: true,
      accessToken: result.accessToken,
    };
  }

  // Logout
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const token = req.headers.authorization?.split(' ')[1];

    if (token) {
      await this.authService.logout(token);
    }

    res.clearCookie('refreshToken');
    return {
      success: true,
      message: 'Logged out successfully',
    };
  }

  // Logout from all devices
  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  async logoutAll(
    @GetUser() user: any,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logoutAll(user.id);
    res.clearCookie('refreshToken');
    return {
      success: true,
      message: 'Logged out from all devices successfully',
    };
  }

  // Get user profile
  @UseGuards(JwtAuthGuard)
  @Get('me')
  async getProfile(@GetUser() user: any) {
    const profile = await this.authService.getUserProfile(user.id);
    return {
      success: true,
      user: profile,
    };
  }

  private setRefreshTokenCookie(res: Response, refreshToken: string) {
    const isProduction = process.env.NODE_ENV === 'production';

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });
  }
}
```

## 14. Get User Decorator

```typescript
// src/auth/decorators/get-user.decorator.ts
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    return data ? user?.[data] : user;
  },
);
```

## 15. Auth Module

```typescript
// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { TokenService } from './services/token.service';

// Strategies
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { FacebookStrategy } from './strategies/facebook.strategy';

// Schemas
import { User, UserSchema } from '../schemas/user.schema';
import { UserToken, UserTokenSchema } from '../schemas/user-token.schema';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({}), // Dynamic configuration
    ConfigModule,
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: UserToken.name, schema: UserTokenSchema },
    ]),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    TokenService,
    LocalStrategy,
    JwtStrategy,
    GoogleStrategy,
    FacebookStrategy,
  ],
  exports: [AuthService, TokenService],
})
export class AuthModule {}
```

## 16. App Module

```typescript
// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { ScheduleModule } from '@nestjs/schedule';

import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MongooseModule.forRootAsync({
      useFactory: () => ({
        uri: process.env.MONGODB_URI,
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }),
    }),
    ScheduleModule.forRoot(),
    AuthModule,
  ],
})
export class AppModule {}
```

## 17. Email Service (for OTP)

```typescript
// src/auth/services/email.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class EmailService {
  constructor(private configService: ConfigService) {}

  async sendOtpEmail(email: string, otp: string, name?: string): Promise<void> {
    // In production, integrate with email service (SendGrid, SES, Nodemailer, etc.)
    console.log(`
      ========================================
      OTP Email for: ${email}
      Name: ${name || 'User'}
      OTP Code: ${otp}

      Subject: Verify Your Account

      Hi ${name || 'there'},

      Your verification code is: ${otp}

      This code will expire in 10 minutes.

      If you didn't create an account, please ignore this email.

      Thanks,
      Your App Team
      ========================================
    `);

    // TODO: Implement actual email sending
    /*
    const transporter = nodemailer.createTransporter({
      // your email config
    });

    await transporter.sendMail({
      from: this.configService.get('FROM_EMAIL'),
      to: email,
      subject: 'Verify Your Account',
      html: `
        <h1>Verify Your Account</h1>
        <p>Hi ${name || 'there'},</p>
        <p>Your verification code is: <strong>${otp}</strong></p>
        <p>This code will expire in 10 minutes.</p>
        <p>If you didn't create an account, please ignore this email.</p>
      `,
    });
    */
  }

  async sendWelcomeEmail(email: string, name?: string): Promise<void> {
    console.log(`Welcome email sent to ${email} (${name})`);
    // TODO: Implement welcome email
  }
}
```

## 18. Frontend Integration Examples

```typescript
// utils/api.ts
class ApiClient {
  private baseURL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';
  private accessToken: string | null = null;

  setAccessToken(token: string) {
    this.accessToken = token;
    if (typeof window !== 'undefined') {
      localStorage.setItem('accessToken', token);
    }
  }

  getAccessToken(): string | null {
    if (this.accessToken) return this.accessToken;

    if (typeof window !== 'undefined') {
      this.accessToken = localStorage.getItem('accessToken');
    }

    return this.accessToken;
  }

  async request(endpoint: string, options: RequestInit = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const token = this.getAccessToken();

    const config: RequestInit = {
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
      ...options,
    };

    let response = await fetch(url, config);

    // Token expired hole refresh try
    if (response.status === 401) {
      const refreshed = await this.refreshToken();

      if (refreshed) {
        // Retry original request
        config.headers = {
          ...config.headers,
          Authorization: `Bearer ${this.getAccessToken()}`,
        };
        response = await fetch(url, config);
      } else {
        // Redirect to login
        if (typeof window !== 'undefined') {
          window.location.href = '/login';
        }
        throw new Error('Authentication failed');
      }
    }

    return response;
  }

  async refreshToken(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseURL}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        this.setAccessToken(data.accessToken);
        return true;
      }
    } catch (error) {
      console.error('Refresh token failed:', error);
    }

    // Clear invalid token
    this.accessToken = null;
    if (typeof window !== 'undefined') {
      localStorage.removeItem('accessToken');
    }

    return false;
  }

  // Auth methods
  async register(userData: {
    email: string;
    username: string;
    password: string;
    name?: string;
    phone?: string;
  }) {
    const response = await fetch(`${this.baseURL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData),
    });

    return response.json();
  }

  async verifyOtp(email: string, otp: string) {
    const response = await fetch(`${this.baseURL}/auth/verify-otp`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, otp }),
    });

    if (response.ok) {
      const data = await response.json();
      this.setAccessToken(data.accessToken);
      return data;
    }

    throw new Error('OTP verification failed');
  }

  async resendOtp(email: string) {
    const response = await fetch(`${this.baseURL}/auth/resend-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });

    return response.json();
  }

  async login(email: string, password: string) {
    const response = await fetch(`${this.baseURL}/auth/login`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (response.ok) {
      const data = await response.json();
      this.setAccessToken(data.accessToken);
      return data;
    }

    throw new Error('Login failed');
  }

  // Social login methods
  loginWithGoogle() {
    window.location.href = `${this.baseURL}/auth/google`;
  }

  loginWithFacebook() {
    window.location.href = `${this.baseURL}/auth/facebook`;
  }

  async logout() {
    await this.request('/auth/logout', { method: 'POST' });
    this.accessToken = null;
    if (typeof window !== 'undefined') {
      localStorage.removeItem('accessToken');
    }
  }

  async getProfile() {
    const response = await this.request('/auth/me');
    return response.json();
  }
}

export const apiClient = new ApiClient();
```

## 19. React Components

```tsx
// components/LoginForm.tsx
import React, { useState } from 'react';
import { apiClient } from '../utils/api';

export const LoginForm: React.FC = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const result = await apiClient.login(formData.email, formData.password);
      console.log('Login successful:', result);
      // Redirect to dashboard
      window.location.href = '/dashboard';
    } catch (error) {
      setError('Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleSocialLogin = (provider: 'google' | 'facebook') => {
    if (provider === 'google') {
      apiClient.loginWithGoogle();
    } else {
      apiClient.loginWithFacebook();
    }
  };

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-6 text-center">Login</h2>

      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">Email</label>
          <input
            type="email"
            value={formData.email}
            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">Password</label>
          <input
            type="password"
            value={formData.password}
            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </form>

      <div className="mt-6">
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300" />
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white text-gray-500">Or continue with</span>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-2 gap-3">
          <button
            onClick={() => handleSocialLogin('google')}
            className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-500 bg-white hover:bg-gray-50"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              {/* Google Icon */}
              <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
              <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
              <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
            </svg>
            <span className="ml-2">Google</span>
          </button>

          <button
            onClick={() => handleSocialLogin('facebook')}
            className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-500 bg-white hover:bg-gray-50"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              {/* Facebook Icon */}
              <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/>
            </svg>
            <span className="ml-2">Facebook</span>
          </button>
        </div>
      </div>
    </div>
  );
};

// components/RegisterForm.tsx
import React, { useState } from 'react';
import { apiClient } from '../utils/api';

export const RegisterForm: React.FC = () => {
  const [step, setStep] = useState(1); // 1: register, 2: verify OTP
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    name: '',
    phone: '',
  });
  const [otp, setOtp] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const result = await apiClient.register(formData);
      setSuccess(result.message);
      setStep(2);
    } catch (error) {
      setError('Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const result = await apiClient.verifyOtp(formData.email, otp);
      console.log('Verification successful:', result);
      // Redirect to dashboard
      window.location.href = '/dashboard';
    } catch (error) {
      setError('Invalid OTP. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleResendOtp = async () => {
    setLoading(true);
    try {
      await apiClient.resendOtp(formData.email);
      setSuccess('OTP sent successfully!');
    } catch (error) {
      setError('Failed to resend OTP.');
    } finally {
      setLoading(false);
    }
  };

  if (step === 2) {
    return (
      <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-md">
        <h2 className="text-2xl font-bold mb-6 text-center">Verify Your Email</h2>

        {error && (
          <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
            {error}
          </div>
        )}

        {success && (
          <div className="mb-4 p-3 bg-green-100 border border-green-400 text-green-700 rounded">
            {success}
          </div>
        )}

        <p className="mb-4 text-gray-600">
          We've sent a 6-digit verification code to {formData.email}
        </p>

        <form onSubmit={handleVerifyOtp} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">OTP Code</label>
            <input
              type="text"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter 6-digit code"
              maxLength={6}
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50"
          >
            {loading ? 'Verifying...' : 'Verify Email'}
          </button>
        </form>

        <div className="mt-4 text-center">
          <button
            onClick={handleResendOtp}
            className="text-blue-600 hover:text-blue-800 text-sm"
            disabled={loading}
          >
            Didn't receive code? Resend
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-6 text-center">Create Account</h2>

      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}

      <form onSubmit={handleRegister} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">Email *</label>
          <input
            type="email"
            value={formData.email}
            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">Username *</label>
          <input
            type="text"
            value={formData.username}
            onChange={(e) => setFormData({ ...formData, username: e.target.value })}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">Password *</label>
          <input
            type="password"
            value={formData.password}
            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            minLength={6}
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">Full Name</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">Phone</label>
          <input
            type="tel"
            value={formData.phone}
            onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? 'Creating Account...' : 'Create Account'}
        </button>
      </form>
    </div>
  );
};
```

## Final Setup Commands

```bash
# Install all dependencies
npm install @nestjs/jwt @nestjs/passport passport passport-jwt passport-local
npm install @nestjs/mongoose mongoose
npm install bcryptjs class-validator class-transformer @nestjs/config
npm install passport-google-oauth20 passport-facebook
npm install @types/bcryptjs @types/passport-local @types/passport-google-oauth20 @types/passport-facebook --save-dev

# Start MongoDB
mongod

# Start NestJS application
npm run start:dev
```

এই implementation এ আপনার সব requirements পূরণ হয়েছে:

✅ **Local Authentication:**
- Email/Password registration with OTP verification
- Passport-Local strategy for login

✅ **Social Authentication:**
- Google OAuth2 login
- Facebook OAuth login
- No account linking (simple approach)

✅ **Database Token Management:**
- JWT tokens stored in database with validation
- Refresh token functionality
- Token cleanup and security

✅ **Your Existing Schema:**
- কোন schema change প্রয়োজন নেই
- `userType` field দিয়ে auth method track করা হচ্ছে

**Key Features:**
- OTP-based email verification for local registration
- Social login redirects to frontend with tokens
- Database token validation for security
- Logout from single/all devices
- Complete frontend integration examples

এখন আপনার users তিনটি উপায়ে authentication করতে পারবে - Email/Password (with OTP verification),
