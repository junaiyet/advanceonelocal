import {
  Table,
  Column,
  Model,
  BelongsTo,
  ForeignKey,
  BeforeSave,
  HasMany,
} from "sequelize-typescript";
import { UserType } from "./UserType.model";
import * as bcrypt from "bcryptjs";
import to from "await-to-js";
import * as jsonwebtoken from "jsonwebtoken";
import { ENV } from "../config";
import { UserAccessSetting } from "./UserAccessSetting.model";
import { UserFeature } from "./UserFeature.model";

@Table({ timestamps: true })
export class User extends Model<User> {
  @Column({ primaryKey: true, autoIncrement: true })
  id: number;

  @Column
  firstName: string;

  @Column
  lastName: string;

  @ForeignKey(() => UserAccessSetting)
  @Column
  userAccessSettingId: number;

  @BelongsTo(() => UserAccessSetting)
  userAccessSettings: UserAccessSetting;

  @HasMany(() => UserFeature)
  userFeatures: UserFeature[];

  @Column
  email: string;

  @Column({ unique: true })
  username: string;

  @Column
  password: string;

  @Column
  passwordValidTill: Date;

  @Column
  sessionExpired: boolean;

  @Column
  phone: string;

  @Column
  status: string;

  @ForeignKey(() => UserType)
  @Column
  userTypeId: number;

  @BelongsTo(() => UserType)
  userType: UserType;

  jwt: string;
  login: boolean;
  @BeforeSave
  static async hashPassword(user: User) {
    let err;
    if (user.changed("password")) {
      let salt, hash;
      [err, salt] = await to(bcrypt.genSalt(10));
      if (err) {
        throw err;
      }

      [err, hash] = await to(bcrypt.hash(user.password, salt));
      if (err) {
        throw err;
      }
      user.password = hash;
    }

    /*
    if (user.changed('phone')){
      let changed = user.phone;
      if (changed && changed.charAt(0) == "0") {
        changed = "61" + changed.substring(1);
      }
      user.phone = changed;
    }
    */
  }

  async comparePassword(pw) {
    let err, pass;
    if (!this.password) {
      throw new Error("Does not have password");
    }

    [err, pass] = await to(bcrypt.compare(pw, this.password));
    if (err) {
      throw err;
    }

    if (!pass) {
      throw "Invalid password";
    }

    return this;
  }

  getJwt() {
    return (
      "Bearer " +
      jsonwebtoken.sign(
        {
          id: this.id,
        },
        ENV.JWT_ENCRYPTION,
        { algorithm: "HS256", expiresIn: ENV.JWT_EXPIRATION }
      )
    );
  }
}
