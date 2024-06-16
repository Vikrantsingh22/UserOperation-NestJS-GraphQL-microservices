import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../../../prisma/Prisma.service';
import { ConfigService } from '@nestjs/config';
import { Observable } from 'rxjs';
import { GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const gqlContext = GqlExecutionContext.create(context);
    const { req } = gqlContext.getContext();
    // console.log('req', req.headers);
    console.log('req', req.headers.accesstoken);
    const accessToken = req.headers.accesstoken as string;
    const refreshToken = req.headers.refreshtoken as string;
    console.log('accessToken', accessToken);
    if (!accessToken || !refreshToken) {
      throw new UnauthorizedException('Please Login to access this resource');
    }
    if (accessToken) {
      console.log('accessToken', accessToken);
      const decoded = await this.jwtService.verify(accessToken, {
        secret: this.config.get<string>('ACCESS_TOKEN_EXPIRE'),
      });
      console.log('decoded', decoded);
      if (!decoded) {
        throw new UnauthorizedException('Invalid acces token!');
      }
      await this.updateAccessToken(req);
    }
    return true;
  }
  private async updateAccessToken(req: any): Promise<void> {
    try {
      console.log('updateAccessToken');
      const refreshTokenData = req.headers.refreshtoken as string;
      const decoded = this.jwtService.verify(refreshTokenData, {
        secret: this.config.get<string>('REFRESH_TOKEN_SECRET'),
      });
      if (!decoded) {
        throw new UnauthorizedException('Invalid refreshToken');
      }
      const user = await this.prisma.user.findUnique({
        where: {
          id: decoded.id,
        },
      });

      const accessToken = this.jwtService.sign(
        { id: user.id },
        {
          secret: this.config.get<string>('ACCESS_TOKEN_EXPIRE'),
          expiresIn: '15m',
        },
      );

      const refreshtoken = this.jwtService.sign(
        { id: user.id },
        {
          secret: this.config.get<string>('REFRESH_TOKEN_SECRET'),
          expiresIn: '7d',
        },
      );
      req.accessToken = accessToken;
      req.refreshToken = refreshtoken;
      req.user = user;
    } catch (error) {
      console.log(error);
    }
  }
}
