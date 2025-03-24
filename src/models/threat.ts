import { pre, prop } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";

/**
 * Interface kế thừa từ Base để sử dụng các thuộc tính mặc định của Typegoose
 */
export interface Threat extends Base {}

/**
 * Lớp DetailScore chứa các thông số chi tiết dùng để tính điểm đánh giá mối đe dọa
 */
class DetailScore {
  @prop({ type: Number, required: true })
  public damage!: number; // Mức độ thiệt hại do threat gây ra

  @prop({ type: Number, required: true })
  public reproducibility!: number; // Mức độ dễ tái hiện lại threat

  @prop({ type: Number, required: true })
  public exploitability!: number; // Mức độ khai thác threat

  @prop({ type: Number, required: true })
  public affectedUsers!: number; // Số lượng người bị ảnh hưởng

  @prop({ type: Number, required: true })
  public discoverability!: number; // Mức độ dễ phát hiện threat
}

/**
 * Lớp Score chứa tổng điểm và chi tiết điểm của threat
 */
class Score {
  @prop({ type: Number, required: true })
  public total!: number; // Tổng điểm threat

  @prop({ type: DetailScore, required: true })
  public details!: DetailScore; // Chi tiết điểm threat
}

/**
 * Tiền xử lý (pre-hook) trước khi lưu Threat vào database
 * => Tự động tính toán tổng điểm dựa trên các chi tiết điểm
 */
@pre<Threat>("save", function (next) {
  this.score.total =
    (this.score.details.damage +
      this.score.details.reproducibility +
      this.score.details.exploitability +
      this.score.details.affectedUsers +
      this.score.details.discoverability) / 5;
  next();
})
export class Threat {
  @prop({ required: true, type: String })
  public name!: string; // Tên của threat

  @prop({ required: true, type: String })
  public description!: string; // Mô tả threat

  @prop({
    required: true,
    type: String,
    enum: [
      "Spoofing",
      "Tampering",
      "Repudiation",
      "Information Disclosure",
      "Denial of Service",
      "Elevation of Privilege",
    ],
  })
  public type!: string; // Loại threat (dựa trên STRIDE)

  @prop({ type: [String], required: true, default: [] })
  public mitigation!: string[]; // Các biện pháp giảm thiểu threat

  @prop({ type: Score, required: true })
  public score!: Score; // Điểm đánh giá của threat

  @prop({
    type: String,
    required: true,
    enum: ["Non mitigated", "Partially mitigated", "Fully mitigated"],
    default: "Non mitigated",
  })
  public status!: string; // Trạng thái giảm thiểu của threat
}
