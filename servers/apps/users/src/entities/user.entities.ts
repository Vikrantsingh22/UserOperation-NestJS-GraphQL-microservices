import { ObjectType, Field, Directive } from '@nestjs/graphql';

@ObjectType()
@Directive('@key(fields:"id")')
export class Avatars {
  @Field()
  id: string;
  @Field()
  public_id: string;
  @Field()
  userId: string;
  @Field()
  url: string;
}
@ObjectType()
export class User {
  @Field()
  id: string;
  @Field()
  name: string;
  @Field()
  email: string;
  @Field()
  password: string;
  @Field()
  role: string;
  @Field()
  phone_number: number;
  @Field()
  createdAt: Date;
  @Field()
  updatedAt: Date;
  @Field(() => Avatars, {
    nullable: true,
  })
  avatar?: Avatars | null;
}
