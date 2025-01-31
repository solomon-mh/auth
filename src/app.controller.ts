import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { Request } from 'express';
import { AuthGuard } from './guards/auth.guard';

export type RequestWithId = {
  request: Request;
  userId: string;
};

@UseGuards(AuthGuard)
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  someProtectedRoute(@Req() request: RequestWithId) {
    return {
      message: 'Accessed Resource',
      userId: request.userId,
    };
  }
}
