import { isDocumentArray } from "@typegoose/typegoose";
import { Request, Response } from "express";
import { ArtifactModel, ProjectModel, ThreatModel, PhaseModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { autoCreateTicketFromThreat, updateTicketStatusForThreat } from "./ticket.controller";
import { validateArtifact } from "../utils/validateArtifact";
import { scanArtifact } from "./phase.controller";
import { ArtifactWorkflowController } from "./artifactWorkflow.controller";
import { createThreatFromVuln } from "./threat.controller";


// Lấy tất cả artifacts thuộc về một project cụ thể
export async function getAll(req: Request, res: Response) {
  const { projectName } = req.query;
  try {
    // Tìm project theo tên và populate danh sách phase cùng artifacts của nó
    const project = await ProjectModel.findOne({
      name: projectName,
    }).populate({
      path: "phaseList",
      populate: {
        path: "artifacts",
        // Bao gồm các trường workflow
        select: '_id name type url version threatList vulnerabilityList cpe isScanning state currentWorkflowStep workflowCycles currentWorkflowCycle workflowCyclesCount'
      }
    });

    // Nếu không tìm thấy project, trả về lỗi
    if (!project) {
      return res.json(errorResponse("Project not found"));
    }

    // Kiểm tra nếu phaseList là một mảng tài liệu hợp lệ
    if (isDocumentArray(project.phaseList)) {
      // Lấy tất cả artifacts từ các phase
      const artifacts = project.phaseList
        .map((phase: any) => phase.artifacts)
        .flat();

      // Trả về danh sách artifacts kèm theo thông báo thành công
      return res.json(
        successResponse(
          artifacts,
          "Get all artifacts with respective vulnerabilities"
        )
      );
    } else {
      // Nếu phaseList không phải là mảng tài liệu hợp lệ
      return res.json(
        successResponse(
          [],
          "No valid artifacts found for this project"
        )
      );
    }
  } catch (error) {
    // Xử lý lỗi nếu có vấn đề trong quá trình lấy dữ liệu
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

// Lấy một artifact cụ thể dựa trên ID
export async function get(req: Request, res: Response) {
  const { id } = req.params;
  try {
    // Tìm artifact theo ID
    const artifact = await ArtifactModel.findById(id);

    // Trả về artifact nếu tìm thấy
    return res.json(successResponse(artifact, "Artifact fetched successfully"));
  } catch (error) {
    // Xử lý lỗi nếu có
    return res.json(error);
  }
}

// Cập nhật artifact với dữ liệu mới và danh sách threats
export async function update(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  console.log(data);

  // Xác thực artifact trước khi tiếp tục
  const validationResult = await validateArtifact(data);

  // Đặt trạng thái dựa trên kết quả xác thực
  data.state = validationResult.valid ? "valid" : "invalid";

  try {
    // Cập nhật artifact với dữ liệu mới
    const artifact = await ArtifactModel.findByIdAndUpdate(
      id,
      {
        ...data,
      },
      {
        new: true, // Trả về artifact sau khi đã cập nhật
      }
    );

    if (!artifact) {
      return res.json(errorResponse("Artifact not found"));
    }    // Tìm phase chứa artifact này
    const phase = await PhaseModel.findOne({ artifacts: artifact._id });

    if (!phase) {
      return res.json(errorResponse("Phase containing this artifact not found"));
    }

    // ✅ Bắt đầu scan ở background chỉ khi artifact hợp lệ
    if (artifact.state === "valid") {
      res.json(successResponse(null, "Artifact updated successfully and scanning started in background"));
      setImmediate(async () => {
        try {
          // Đảm bảo phase và phase._id tồn tại trước khi gọi scanArtifact
          if (phase && phase._id) {
            await scanArtifact(artifact, phase._id.toString());
          } else {
            console.error("[ERROR] Phase or phase._id is null/undefined during scanning");
          }
        } catch (error) {
          console.error("[ERROR] Scanning failed:", error);
        }
      });
    } else {
      res.json(successResponse(null, `Artifact updated successfully but is not valid: ${validationResult.error}`));
    }

  } catch (error) {
    console.error("[ERROR] Internal server error", error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function updateRateScan(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  const { rate } = data;

  //kiểm tra xem role có phải manager không
  const user = req.user;
  if (!user || user.role !== "project_manager") {
    return res.json(errorResponse("You are not authorized to update this artifact"));
  }

  try {
    if (rate < 0 || rate > 100) {
      return res.json(errorResponse("Rate must be between 0 and 100"));
    }

    // Cập nhật artifact với dữ liệu mới và danh sách threats
    const artifact = await ArtifactModel.findByIdAndUpdate(
      id,
      {
        rateReScan: rate// Gán danh sách threats vào artifact
      },
      {
        new: true, // Trả về artifact sau khi đã cập nhật
      }
    );

    // Trả về artifact sau khi cập nhật thành công
    return res.json(successResponse(artifact, "Rate re-scan updated successfully"));
  } catch (error) {
    // Xử lý lỗi nếu có vấn đề trong quá trình cập nhật
    return res.json(error);
  }
}

// Hàm gộp danh sách lỗ hổng và loại bỏ trùng lặp
function mergeVulnerabilities(existingVulns: any[], newVulns: any[]): any[] {
  const merged = [...existingVulns];

  for (const newVuln of newVulns) {
    const exists = merged.some(v => v.cveId === newVuln.cveId);
    if (!exists) {
      merged.push(newVuln);
    }
  }

  return merged;
}

// Hàm xử lý kết quả từ một scanner
export async function processScannerResult(artifactId: string, vulns: any): Promise<void> {
  try {
    const artifact = await ArtifactModel.findById(artifactId);
    if (!artifact) {
      console.error(`Artifact ${artifactId} not found`);
      return;
    }
     // Gộp các lỗ hổng mới với tempVuls hiện có
    const updatedTempVuls = mergeVulnerabilities(artifact.tempVuls || [], vulns);

    // Tăng số lượng scanner đã hoàn thành
    const completedScanners = (artifact.scannersCompleted || 0) + 1;

    console.log(`Scanner result processed for artifact ${artifactId}. Total completed scanners: ${completedScanners} of ${artifact.totalScanners}`);    // Kiểm tra xem tất cả scanner đã hoàn thành chưa
    if (completedScanners >= (artifact.totalScanners ?? 1)) {
      // Đầu tiên cập nhật tempVuls và trạng thái scanner, bao gồm việc set isScanning = false
      console.log(`[DEBUG] All scanners completed. Processing ${updatedTempVuls.length} vulnerabilities`);

      // Cập nhật trạng thái hoàn thành scan
      await ArtifactModel.findByIdAndUpdate(
        artifactId,
        {
          $set: {
            tempVuls: updatedTempVuls,
            scannersCompleted: 0,
            totalScanners: 0,
            numberThreatSubmitted: 0,
            isScanning: false // ✅ Set isScanning to false when all scanners complete
          }
        }
      );

      // Lấy bản sao mới của artifact và đảm bảo tempVuls được điền
      const freshArtifact = await ArtifactModel.findById(artifactId);
      if (freshArtifact) {
        // Đảm bảo tempVuls có sẵn
        if (!freshArtifact.tempVuls || freshArtifact.tempVuls.length === 0) {
          freshArtifact.tempVuls = updatedTempVuls;
          await freshArtifact.save();
        }

        await updateArtifactAfterScan(freshArtifact);
      } else {
        console.error(`[ERROR] Could not retrieve fresh artifact after scanner completion`);
      }
    } else {
      // Chỉ cập nhật số scanner đã hoàn thành và tempVuls
      console.log(`[DEBUG] Scanner ${completedScanners}/${artifact.totalScanners} completed with ${updatedTempVuls.length} vulnerabilities`);
      await ArtifactModel.findByIdAndUpdate(
        artifactId,
        {
          $set: {
            tempVuls: updatedTempVuls,
            scannersCompleted: completedScanners
          }
        }
      );
    }

  } catch (error) {
    console.error("Error processing scanner result:", error);
    throw error;
  }
}

/**
 * Kiểm tra threat có phù hợp với vulnerability không. 
 * Giả sử threat.name chứa định danh (ví dụ cveId) của vulnerability.
 */
function threatMatchesVul(threat: any, vuln: any): boolean {
  return threat.name === vuln.cveId;
}

/**
 * Xử lý từng threat hiện có trong artifact.threatList:
 * - Nếu có vulnerability tương ứng trong tempVuls thì cập nhật ticket thành "Processing".
 * - Nếu không có thì cập nhật ticket thành "Resolved" và xóa threat khỏi DB cũng như khỏi artifact.
 */
async function processExistingThreats(artifact: any): Promise<void> {
  // Bỏ qua nếu không có tempVuls hoặc không có threat hiện có
  if (!artifact.tempVuls || artifact.tempVuls.length === 0 || !artifact.threatList || artifact.threatList.length === 0) {
    console.log(`[DEBUG] No tempVuls or no existing threats to process`);
    return;
  }

  // Đảm bảo threatList đã được populate
  await artifact.populate("threatList");

  // Lưu danh sách threatId cần loại bỏ sau này
  const threatsToRemove: any[] = [];

  // Đảm bảo threatList là một mảng
  if (!Array.isArray(artifact.threatList)) {
    console.log(`[WARN] artifact.threatList is not an array`);
    return;
  }

  for (const threat of artifact.threatList) {
    if (!threat || !threat._id) {
      console.log(`[WARN] Invalid threat found in threatList, skipping`);
      continue;
    }

    // Kiểm tra có tồn tại vulnerability tương ứng trong tempVuls
    const existsInTemp = artifact.tempVuls?.some((vuln: any) => threatMatchesVul(threat, vuln));

    if (existsInTemp) {
      // Cập nhật trạng thái ticket của threat thành "Processing"
      await updateTicketStatusForThreat(threat._id, false);
    } else {
      // Cập nhật trạng thái ticket của threat thành "Resolved"
      await updateTicketStatusForThreat(threat._id, true);
      // Đánh dấu threat này để xóa
      threatsToRemove.push(threat._id);
    }
  }

  // Chỉ cập nhật artifact nếu có threat cần xóa
  if (threatsToRemove.length > 0) {
    // Loại bỏ các threat đã bị xóa khỏi artifact.threatList (không xóa khỏi database)
    const updatedThreatList = artifact.threatList.filter(
      (t: any) => !threatsToRemove.some((removeId: any) => removeId.toString() === t._id.toString())
    );

    // Cập nhật artifact với threatList mới
    await ArtifactModel.findByIdAndUpdate(
      artifact._id,
      { $set: { threatList: updatedThreatList } },
      { new: true }
    );
  }

  try {
    await ArtifactWorkflowController.updateWorkflowStatus(artifact._id, 5);
  } catch (workflowError) {
    console.error(`[ERROR] Failed to update workflow status:`, workflowError);
    // Không ném lỗi ở đây vì chúng ta không muốn chặn việc cập nhật ticket
  }
}

/**
 * Xử lý danh sách vulnerability mới từ artifact.tempVuls:
 * Với mỗi vulnerability trong tempVuls, nếu nó không có trong artifact.vulnerabilityList,
 * thì tạo threat mới và thêm vào artifact.threatList.
 */
async function processNewVulnerabilities(artifact: any): Promise<void> {
  let threatCount = 0;
  const newThreatIds: any[] = [];

  if (!artifact.tempVuls || artifact.tempVuls.length === 0) {
    console.log(`[WARN] No vulnerabilities to process in artifact ${artifact._id}`);
    return;
  }

  // Đảm bảo artifact.threatList tồn tại
  if (!artifact.threatList) {
    artifact.threatList = [];
  }

  for (const newVul of artifact.tempVuls) {
    // Đảm bảo chúng ta có vulnerability hợp lệ 
    if (!newVul || !newVul.cveId) {
      console.log(`[WARN] Invalid vulnerability found, skipping`);
      continue;
    }

    // Kiểm tra nếu vulnerability này chưa tồn tại trong artifact.vulnerabilityList
    const exists = artifact.vulnerabilityList?.some(
      (oldVul: any) => oldVul.cveId === newVul.cveId
    );

    if (!exists) {
      try {
        // Kiểm tra xem đã có threat trong database với cùng tên (cveId) hay chưa
        let existingThreat = await ThreatModel.findOne({ name: newVul.cveId });
        
        let threatToUse;
        if (existingThreat) {
          // Sử dụng threat đã có sẵn
          threatToUse = existingThreat;
        } else {
          // Tạo threat mới với dữ liệu vulnerability
          const threatData = createThreatFromVuln(newVul);
          threatToUse = await ThreatModel.create(threatData);
        }

        // Kiểm tra xem threat đã có trong threatList của artifact chưa
        const threatAlreadyInList = artifact.threatList.some(
          (existingThreatId: any) => existingThreatId.toString() === threatToUse._id.toString()
        );

        if (!threatAlreadyInList) {
          // Thêm vào danh sách threat của artifact
          artifact.threatList.push(threatToUse._id);
          newThreatIds.push(threatToUse._id);

          // Tạo ticket cho threat
          await autoCreateTicketFromThreat(artifact._id, threatToUse._id);

          threatCount++;
        } else {
          console.log(`[DEBUG] Threat ${newVul.cveId} already exists in artifact threatList`);
        }
      } catch (err) {
        console.error(`[ERROR] Failed to process vulnerability ${newVul.cveId}:`, err);
      }
    }
  }

  // Lưu threatList đã cập nhật
  await ArtifactModel.findByIdAndUpdate(
    artifact._id,
    {
      $set: { threatList: artifact.threatList }
    },
    { new: true }
  );

  console.log(`[INFO] Created ${threatCount} new threats from ${artifact.tempVuls.length} vulnerabilities`);
}

/**
 * Hàm cập nhật artifact sau khi scan:
 * 1. Xử lý threat hiện có
 * 2. Xử lý các vulnerability mới (tempVuls)
 * 3. Cập nhật artifact.vulnerabilityList từ tempVuls và lưu artifact.
 */
export async function updateArtifactAfterScan(artifact: any): Promise<void> {
  try {
    // Đảm bảo chúng ta có artifact đầy đủ với tất cả các trường cần thiết
    const completeArtifact = await ArtifactModel.findById(artifact._id);
    if (!completeArtifact) {
      console.error(`[ERROR] Could not find artifact ${artifact._id}`);
      return;
    }

    // Đảm bảo chúng ta có tempVuls từ artifact gốc nếu không có trong completeArtifact
    if (!completeArtifact.tempVuls || completeArtifact.tempVuls.length === 0) {
      if (artifact.tempVuls && artifact.tempVuls.length > 0) {
        console.log(`[DEBUG] Restoring tempVuls from original artifact object`);
        completeArtifact.tempVuls = artifact.tempVuls;
      }
    }

    // 2. Đầu tiên xử lý các vulnerability mới để tạo threat và ticket
    await processNewVulnerabilities(completeArtifact);

    // 1. Sau đó xử lý các threat hiện có để cập nhật trạng thái của chúng
    await processExistingThreats(completeArtifact);

    // 3. Lưu lịch sử quét vào scanHistory và cập nhật artifact

    // Tạo bản sao của tempVuls để đảm bảo chúng ta không mất chúng trong quá trình cập nhật
    const tempVulsCopy = [...(artifact.tempVuls || [])];

    // Thêm mục lịch sử quét nếu có lỗ hổng
    if (tempVulsCopy.length > 0) {
      await ArtifactModel.findByIdAndUpdate(
        artifact._id,
        {
          $push: {
            scanHistory: {
              timestamp: new Date(),
              vulnerabilities: tempVulsCopy
            }
          }
        },
        { new: true }
      );

    }

    // Bây giờ cập nhật vulnerabilityList và xóa tempVuls
    await ArtifactModel.findByIdAndUpdate(
      artifact._id,
      {
        $set: {
          vulnerabilityList: tempVulsCopy
        },
        $unset: {
          tempVuls: 1 // ✅ Clear tempVuls after processing is complete
        }
      },
      { new: true }
    );

    // 5. Cập nhật trạng thái workflow - chỉ bắt đầu từ step 1 và để workflow tự động tiến triển
    try {
      // Chỉ gọi updateWorkflowStatus cho step 1 (Detection) 
      // Workflow sẽ tự động tiến triển qua các step tiếp theo dựa trên logic trong ArtifactWorkflowController
      await ArtifactWorkflowController.updateWorkflowStatus(artifact._id, 1);
      await ArtifactWorkflowController.updateWorkflowStatus(artifact._id, 2);
      await ArtifactWorkflowController.updateWorkflowStatus(artifact._id, 3);
      
      console.log(`[DEBUG] Workflow status updated for artifact ${artifact._id}, starting from Detection step`);
    } catch (workflowError) {
      console.error(`[ERROR] Failed to update workflow status:`, workflowError);
    }
  } catch (error) {
    console.error("Lỗi khi cập nhật artifact sau scan:", error);
    
    // Đảm bảo isScanning được set về false ngay cả khi có lỗi
    try {
      await ArtifactModel.findByIdAndUpdate(
        artifact._id,
        { isScanning: false },
        { new: true }
      );
      console.log(`[DEBUG] Set isScanning to false for artifact ${artifact._id} due to error`);
    } catch (updateError) {
      console.error(`[ERROR] Failed to update isScanning flag after error:`, updateError);
    }
    
    throw error;
  }
}

// Di chuyển artifact để đảm bảo tất cả đều có trường state
export async function migrateArtifactsState() {
  try {
    // Tìm tất cả artifact không có trường state
    const artifacts = await ArtifactModel.find({ state: { $exists: false } });

    if (artifacts.length === 0) {
      return;
    }

    console.log(`[INFO] Found ${artifacts.length} artifacts without state field, applying migration`);

    // Cập nhật tất cả artifact để đặt state mặc định thành valid
    const updateResult = await ArtifactModel.updateMany(
      { state: { $exists: false } },
      { $set: { state: "valid" } }
    );

    console.log(`[INFO] Migration complete: ${updateResult.modifiedCount} artifacts updated`);
  } catch (error) {
    console.error("[ERROR] Failed to migrate artifact states:", error);
  }
}

// Chạy migration khi khởi động
migrateArtifactsState();

// Lấy ID phase chứa một artifact cụ thể
export async function getPhaseForArtifact(req: Request, res: Response) {
  const { id } = req.params;
  try {
    // Tìm phase chứa artifact này
    const phase = await PhaseModel.findOne({ artifacts: id }).select('_id name');

    if (!phase) {
      return res.json(errorResponse("Phase containing this artifact not found"));
    }

    return res.json(successResponse({ phaseId: phase._id, phaseName: phase.name }, "Phase found successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
