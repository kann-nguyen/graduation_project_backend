import { Request, Response } from 'express';
import { ArtifactModel, TicketModel } from '../models/models';
import { Artifact } from '../models/artifact';
import mongoose from 'mongoose';
import { Ticket } from '../models/ticket';

/**
 * Controller xử lý workflow của artifact (Quy trình làm việc với artifact)
 * Quản lý các chu kỳ workflow: Detection -> Classification -> Assignment -> Remediation -> Verification
 */
export class ArtifactWorkflowController {
  
  /**
   * Lấy lịch sử workflow của một artifact
   * @param req - Express request với artifactId trong params
   * @param res - Express response
   */
  public static async getWorkflowHistory(req: Request, res: Response) {
    try {
      const { artifactId } = req.params;
      
      // Lấy lịch sử workflow
      const history = await ArtifactWorkflowController._getWorkflowHistory(artifactId);
      
      // Kiểm tra nếu chưa có lịch sử
      if (history.length === 0) {
        // Nếu chưa có lịch sử, kiểm tra xem artifact có tồn tại không
        const artifact = await ArtifactModel.findById(artifactId);
        if (artifact) {
          if (!artifact.currentWorkflowCycle) {
            // Khởi tạo workflow nếu cần thiết - sẽ tạo chu kỳ đầu tiên
            await ArtifactWorkflowController._initializeWorkflowCycle(artifactId);
            // Lấy lịch sử đã được cập nhật
            const updatedHistory = await ArtifactWorkflowController._getWorkflowHistory(artifactId);
            return res.status(200).json({
              success: true,
              data: updatedHistory
            });
          }
        }
      }
      
      return res.status(200).json({
        success: true,
        data: history
      });
    } catch (error: any) {
      return res.status(500).json({
        success: false,
        message: error.message || 'Failed to fetch workflow history'
      });
    }
  }
  
  /**
   * Lấy thống kê workflow của một project
   * @param req - Express request với projectId trong params
   * @param res - Express response
   */
  public static async getProjectWorkflowStats(req: Request, res: Response) {
    try {
      const { projectId } = req.params;
      
      const stats = await ArtifactWorkflowController._getProjectWorkflowStats(projectId);
      
      return res.status(200).json({
        success: true,
        data: stats
      });
    } catch (error: any) {
      return res.status(500).json({
        success: false,
        message: error.message || 'Failed to fetch project workflow stats'
      });
    }
  }

  /**
   * Lấy danh sách artifacts theo bước workflow
   * @param req - Express request với projectId trong params và step trong query
   * @param res - Express response
   */
  public static async getArtifactsByWorkflowStep(req: Request, res: Response) {
    try {
      const { projectId } = req.params;
      const { step } = req.query;
      
      const stepNumber = step ? parseInt(step as string) : undefined;
      
      // Tìm artifacts trong project và bước được chỉ định
      const query: any = { projectId };
      if (stepNumber && stepNumber >= 1 && stepNumber <= 5) {
        query.currentWorkflowStep = stepNumber;
      }
      
      const artifacts = await ArtifactModel.find(query);
      
      return res.status(200).json({
        success: true,
        data: artifacts
      });
    } catch (error: any) {
      return res.status(500).json({
        success: false,
        message: error.message || 'Failed to fetch artifacts by workflow step'
      });
    }
  }

   /**
   * Lấy lịch sử workflow của artifact
   * @param artifactId - ID của artifact
   * @returns Mảng các chu kỳ workflow
   */
  private static async _getWorkflowHistory(artifactId: string | mongoose.Types.ObjectId) {
    const artifact = await ArtifactModel.findById(artifactId);
    if (!artifact) {
      throw new Error('Artifact not found');
    }

    // Nếu artifact này chưa có chu kỳ workflow nào, khởi tạo một chu kỳ
    if (!artifact.workflowCycles || artifact.workflowCycles.length === 0) {
      try {
        await this._initializeWorkflowCycle(artifactId);
        
        // Lấy artifact đã cập nhật với chu kỳ workflow mới
        const updatedArtifact = await ArtifactModel.findById(artifactId);
        if (!updatedArtifact) {
          throw new Error('Failed to initialize workflow cycle');
        }
        
        return updatedArtifact.workflowCycles || [];
      } catch (error) {
        // Trả về mảng rỗng trong trường hợp lỗi khởi tạo
        return [];
      }
    }

    return artifact.workflowCycles || [];
  }

  /**
   * Lấy thống kê workflow của project
   * @param projectId - ID của project
   * @returns Thống kê workflow
   */
  private static async _getProjectWorkflowStats(projectId: string | mongoose.Types.ObjectId) {
    const artifacts = await ArtifactModel.find({ projectId });
    
    const stats = {
      totalArtifacts: artifacts.length,
      step1Count: 0,
      step2Count: 0,
      step3Count: 0,
      step4Count: 0,
      step5Count: 0,
      completedArtifacts: 0,
      totalCycles: 0,
      averageCycles: 0,
    };

    artifacts.forEach(artifact => {
      const step = artifact.currentWorkflowStep || 1;
      
      // Đếm artifacts theo bước hiện tại
      if (step === 1) stats.step1Count++;
      if (step === 2) stats.step2Count++;
      if (step === 3) stats.step3Count++;
      if (step === 4) stats.step4Count++;
      if (step === 5) stats.step5Count++;

      // Đếm artifacts đã hoàn thành
      if (artifact.workflowCompleted) {
        stats.completedArtifacts++;
      }

      // Tổng hợp tổng số chu kỳ
      stats.totalCycles += artifact.workflowCyclesCount || 0;
    });

    // Tính trung bình chu kỳ trên mỗi artifact
    stats.averageCycles = stats.totalArtifacts > 0 
      ? stats.totalCycles / stats.totalArtifacts 
      : 0;

    return stats;
  }
  
  /**
   * Khởi tạo chu kỳ workflow mới cho artifact
   * @param artifactId - ID của artifact
   * @returns Artifact đã được cập nhật
   */
  private static async _initializeWorkflowCycle(artifactId: string | mongoose.Types.ObjectId) {
    // Lấy dữ liệu artifact mới nhất
    const artifact = await ArtifactModel.findById(artifactId);
    if (!artifact) {
      throw new Error('Artifact not found');
    }
    
    // Kiểm tra xem có cần tăng số lượng chu kỳ workflow không
    const lastCyclesCount = artifact.workflowCyclesCount || 0;
    const cycleNumber = lastCyclesCount + 1;
    
    // Khởi tạo chu kỳ mới với tất cả các trường bắt buộc
    const newCycle = {
      cycleNumber,
      currentStep: 1, // Bắt đầu ở bước 1 (Detection)
      startedAt: new Date(),
      // Khởi tạo tất cả các bước để đảm bảo chúng tồn tại trong cả currentWorkflowCycle và mảng workflowCycles
      detection: {
        completedAt: new Date(), // Detection được hoàn thành khi chu kỳ bắt đầu
        numberVuls: artifact.vulnerabilityList?.length || 0, // Khởi tạo với số lượng vulnerability hiện tại
        listVuls: []
      },
      classification: {
        numberThreats: artifact.threatList?.length || 0, // Khởi tạo với số lượng threat hiện tại
        listThreats: []
      },
      assignment: {
        numberTicketsAssigned: 0,
        numberTicketsNotAssigned: 0,
        listTickets: []
      },
      remediation: {
        numberTicketsSubmitted: 0, 
        numberTicketsNotSubmitted: 0,
        numberThreatsResolved: 0,
        listTickets: []
      },
      verification: {
        numberTicketsResolved: 0,
        numberTicketsReturnedToProcessing: 0
      }
    };
    
    // Tạo bản sao sâu để đẩy vào mảng workflow cycles
    const deepCopy = JSON.parse(JSON.stringify(newCycle));
    
    // Kiểm tra xem chu kỳ này đã tồn tại trong mảng chưa để tránh trùng lặp
    const existingCycle = artifact.workflowCycles?.find(
      (c: any) => c.cycleNumber === cycleNumber
    );
    
    let updateOperation: any = { 
      $set: {
        workflowCyclesCount: cycleNumber,  // Đặt trực tiếp số chu kỳ hiện tại
        currentWorkflowStep: 1,
        workflowCompleted: false,
        currentWorkflowCycle: newCycle
      }
    };
    
    // Chỉ thêm vào mảng nếu chu kỳ này chưa tồn tại
    if (!existingCycle) {
      updateOperation.$push = { workflowCycles: deepCopy };
    }
    
    // Sử dụng findOneAndUpdate với hoạt động atomic để đảm bảo tính nhất quán
    const updatedArtifact = await ArtifactModel.findOneAndUpdate(
      { _id: artifact._id },
      updateOperation,
      { 
        new: true,  // Trả về document đã cập nhật
        runValidators: true  // Chạy schema validators
      }
    );
    
    if (!updatedArtifact) {
      throw new Error(`Failed to initialize workflow cycle for artifact ${artifact._id}`);
    }
    
    // Xác minh rằng chu kỳ đã được tạo/cập nhật đúng cách
    const finalCheck = await ArtifactModel.findById(artifact._id);
    if (finalCheck) {
      // Kiểm tra xem currentWorkflowCycle có khớp với mong đợi không
      if (!finalCheck.currentWorkflowCycle || finalCheck.currentWorkflowCycle.cycleNumber !== cycleNumber) {
        // Thử sửa nếu cần
        if (!finalCheck.currentWorkflowCycle) {
          await ArtifactModel.findByIdAndUpdate(
            artifact._id,
            { $set: { currentWorkflowCycle: newCycle } }
          );
        }
      }
    }
    
    return updatedArtifact;
  }

  /**
   * Chuyển sang bước tiếp theo trong workflow
   * @param artifactId - ID của artifact
   * @param stepData - Dữ liệu của bước hiện tại
   * @returns Artifact đã được cập nhật
   */
  private static async _moveToNextStep(artifactId: string | mongoose.Types.ObjectId, stepData: any = {}) {
    const artifact = await ArtifactModel.findById(artifactId);    
    if (!artifact) {
      throw new Error('Artifact not found');
    }

    if (!artifact.currentWorkflowCycle) {
      throw new Error('No active workflow cycle');
    }

    const currentStep = artifact.currentWorkflowStep || 1;
    let nextStep = currentStep + 1;
    
    // Cập nhật dữ liệu bước hiện tại với timestamp hoàn thành
    const updatedStepData = {
      ...stepData,
      completedAt: new Date()
    };
    
    // Cập nhật dữ liệu bước hiện tại
    this._updateStepData(artifact, currentStep, updatedStepData);
    
    // Kiểm tra xem đã hoàn thành tất cả các bước chưa
    if (nextStep > 5) {
      // Đánh dấu chu kỳ hiện tại đã hoàn thành bằng cách sử dụng atomic update
      await ArtifactModel.findByIdAndUpdate(
        artifact._id,
        { 
          $set: {
            'currentWorkflowCycle.completedAt': new Date(),
            workflowCyclesCount: artifact.currentWorkflowCycle.cycleNumber, // Đảm bảo count được đặt đúng
            workflowCompleted: true
          }
        },
        { new: true }
      );
      
      // Bắt đầu chu kỳ workflow mới với trạng thái artifact mới
      return await ArtifactWorkflowController._initializeWorkflowCycle(artifact._id);
    }

    // Cập nhật bước hiện tại
    artifact.currentWorkflowStep = nextStep;
    artifact.currentWorkflowCycle.currentStep = nextStep;
    
    // Đồng bộ cuối cùng để đảm bảo tất cả dữ liệu nhất quán
    this._syncWorkflowCycles(artifact);
    // Xác thực tính nhất quán của workflow
    this._validateWorkflowConsistency(artifact);
    await artifact.save();
    
    return artifact;
  }
  
  /**
   * Cập nhật dữ liệu của một bước workflow
   * @param artifact - Artifact cần cập nhật
   * @param step - Số bước (1-5)
   * @param data - Dữ liệu cần cập nhật
   * @returns True nếu thành công, false nếu thất bại
   */
  private static _updateStepData(artifact: Artifact, step: number, data: any) {
    if (!artifact.currentWorkflowCycle) {
      return false;
    }
    
    try {
      switch (step) {
        case 1:
          artifact.currentWorkflowCycle.detection = {
            ...artifact.currentWorkflowCycle.detection,
            ...data
          };
          break;
        case 2:
          if (!artifact.currentWorkflowCycle.classification) {
            artifact.currentWorkflowCycle.classification = {};
          }
          artifact.currentWorkflowCycle.classification = {
            ...artifact.currentWorkflowCycle.classification,
            ...data
          };
          break;
        case 3:
          if (!artifact.currentWorkflowCycle.assignment) {
            artifact.currentWorkflowCycle.assignment = {};
          }
          artifact.currentWorkflowCycle.assignment = {
            ...artifact.currentWorkflowCycle.assignment,
            ...data
          };
          break;
        case 4:
          if (!artifact.currentWorkflowCycle.remediation) {
            artifact.currentWorkflowCycle.remediation = {};
          }
          artifact.currentWorkflowCycle.remediation = {
            ...artifact.currentWorkflowCycle.remediation,
            ...data
          };
          break;
        case 5:
          if (!artifact.currentWorkflowCycle.verification) {
            artifact.currentWorkflowCycle.verification = {};
          }
          artifact.currentWorkflowCycle.verification = {
            ...artifact.currentWorkflowCycle.verification,
            ...data
          };
          break;
        default:
          return false;
      }
      
      // Đồng bộ mảng workflow cycles với chu kỳ workflow hiện tại
      this._syncWorkflowCycles(artifact);
      
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Cập nhật trạng thái workflow cho artifact
   * @param artifactId - ID của artifact
   * @param step - Bước workflow hiện tại (1-5)
   * @returns Artifact đã được cập nhật
   */
  public static async updateWorkflowStatus(artifactId: string | mongoose.Types.ObjectId, step: number): Promise<any> {
    const artifact = await ArtifactModel.findById(artifactId)
      .populate('threatList')
      .populate({
        path: 'vulnerabilityList',
        model: 'Vulnerability'
      });

    if (!artifact) {
      throw new Error('Artifact not found');
    }

    // Khởi tạo chu kỳ workflow nếu chưa có
    if (!artifact.currentWorkflowCycle) {
      return await ArtifactWorkflowController._initializeWorkflowCycle(artifactId);
    }
    
    // Kiểm tra điều kiện cho từng bước và cập nhật nếu cần thiết
    switch (step) {
      case 1: // Bước Detection
        return await ArtifactWorkflowController._checkDetectionStepCompletion(artifact);
      
      case 2: // Bước Classification
        return await ArtifactWorkflowController._checkClassificationStepCompletion(artifact);
      
      case 3: // Bước Assignment
        return await ArtifactWorkflowController._checkAssignmentStepCompletion(artifact);
      
      case 4: // Bước Remediation
        return await ArtifactWorkflowController._checkRemediationStepCompletion(artifact);
      
      case 5: // Bước Verification
        return await ArtifactWorkflowController._checkVerificationStepCompletion(artifact);
      
      default:
        artifact.currentWorkflowStep = 1;
        await artifact.save();
        return artifact;
    }
  }

  /**
   * Kiểm tra hoàn thành bước Detection
   * @param artifact - Artifact cần kiểm tra
   * @returns Artifact đã được cập nhật
   */
  private static async _checkDetectionStepCompletion(artifact: any): Promise<any> {
    // Nếu artifact vẫn đang quét, chưa thể tiến lên bước tiếp theo
    if (artifact.isScanning) {
      return artifact;
    }
    
    // Nếu không có vulnerabilities, vẫn coi là hoàn thành nhưng ghi chú điều này
    const vulnCount = artifact.vulnerabilityList?.length || 0;
    
    // Cập nhật dữ liệu bước detection
    if (artifact.currentWorkflowCycle && artifact.currentWorkflowCycle.detection) {
      artifact.currentWorkflowCycle.detection.listVuls = artifact.vulnerabilityList;
      artifact.currentWorkflowCycle.detection.numberVuls = vulnCount;
      artifact.currentWorkflowCycle.detection.completedAt = new Date();
      // Đồng bộ workflow cycles để đảm bảo tính nhất quán dữ liệu
      this._syncWorkflowCycles(artifact);
    }
    await artifact.save();
    
    // Chuyển sang bước classification
    if (artifact.currentWorkflowStep === 1) 
      return await ArtifactWorkflowController._moveToNextStep(artifact._id);
  }

  /**
   * Kiểm tra hoàn thành bước Classification
   * @param artifact - Artifact cần kiểm tra
   * @returns Artifact đã được cập nhật
   */
  private static async _checkClassificationStepCompletion(artifact: any): Promise<any> {
    // Đếm threat
    const threatCount = artifact.threatList?.length || 0;
    
    // Nếu có threats, cập nhật dữ liệu bước classification và tiến lên
    if (threatCount > 0) {
      // Cập nhật dữ liệu bước classification
      if (artifact.currentWorkflowCycle) {
        if (!artifact.currentWorkflowCycle.classification) {
          artifact.currentWorkflowCycle.classification = {};
        }
        
        // Lưu trữ ID của threats trong dữ liệu bước classification
        artifact.currentWorkflowCycle.classification.listThreats = artifact.threatList.map((threat: any) => 
          typeof threat === 'object' ? threat._id : threat
        );
        artifact.currentWorkflowCycle.classification.numberThreats = threatCount;
        artifact.currentWorkflowCycle.classification.completedAt = new Date();
        
        // Đồng bộ workflow cycles để đảm bảo tính nhất quán dữ liệu
        this._syncWorkflowCycles(artifact);
        
        await artifact.save();
      }
      
      if (artifact.currentWorkflowStep === 2) 
        return await ArtifactWorkflowController._moveToNextStep(artifact._id);
    }
    
    // Nếu không có threats, kiểm tra xem có cần đánh dấu detection hoàn thành
    // Điều này xảy ra nếu tất cả vulnerabilities đã được giải quyết trong chu kỳ trước
    const vulnerabilityCount = artifact.vulnerabilityList?.length || 0;
    if (vulnerabilityCount === 0 && threatCount === 0) {
      artifact.workflowCompleted = true;
      await artifact.save();
    }
    
    return artifact;
  }

  /**
   * Kiểm tra hoàn thành bước Assignment
   * @param artifact - Artifact cần kiểm tra
   * @returns Artifact đã được cập nhật
   */
  private static async _checkAssignmentStepCompletion(artifact: any): Promise<any> {    
    // Lấy số lượng và danh sách tickets
    const {
      tickets,
      assigned: assignedTickets,
      unassigned: unassignedTickets
    } = await ArtifactWorkflowController._getTicketCounts(artifact._id);
        
    // Cập nhật dữ liệu bước assignment
    if (artifact.currentWorkflowCycle) {
      if (!artifact.currentWorkflowCycle.assignment) {
        artifact.currentWorkflowCycle.assignment = {};
      }
      
      artifact.currentWorkflowCycle.assignment.listTickets = tickets.map((t: any) => t._id);
      artifact.currentWorkflowCycle.assignment.numberTicketsAssigned = assignedTickets.length;
      artifact.currentWorkflowCycle.assignment.numberTicketsNotAssigned = unassignedTickets.length;
      
      await artifact.save();
    }
    
    // Nếu ít nhất một ticket được phân công, chuyển sang bước remediation
    if (assignedTickets.length > 0) {
      if (artifact.currentWorkflowStep === 3) 
        return await ArtifactWorkflowController._moveToNextStep(artifact._id);
    }
    
    return artifact;
  }

  /**
   * Kiểm tra hoàn thành bước Remediation
   * @param artifact - Artifact cần kiểm tra
   * @returns Artifact đã được cập nhật
   */
  private static async _checkRemediationStepCompletion(artifact: any): Promise<any> {
    // Lấy số lượng và danh sách tickets bằng phương thức tiện ích
    const {
      tickets,
      submitted: submittedTickets,
      notSubmitted: notSubmittedTickets,
      resolved: resolvedTickets
    } = await ArtifactWorkflowController._getTicketCounts(artifact._id);
        
    // Cập nhật dữ liệu bước remediation
    if (artifact.currentWorkflowCycle) {
      if (!artifact.currentWorkflowCycle.remediation) {
        artifact.currentWorkflowCycle.remediation = {};
      }
      
      artifact.currentWorkflowCycle.remediation.listTickets = tickets.map((t: any) => t._id);
      artifact.currentWorkflowCycle.remediation.numberTicketsSubmitted = submittedTickets.length;
      artifact.currentWorkflowCycle.remediation.numberTicketsNotSubmitted = notSubmittedTickets.length;
      artifact.currentWorkflowCycle.remediation.completedAt = submittedTickets.length > 0 ? new Date() : undefined;
      
      await artifact.save();
    }
    
    // Nếu ít nhất một ticket được submit/resolve, chuyển sang bước verification
    if (submittedTickets.length > 0) {
      if (artifact.currentWorkflowStep === 4) 
        return await ArtifactWorkflowController._moveToNextStep(artifact._id);
    }
    
    return artifact;
  }

  /**
   * Kiểm tra hoàn thành bước Verification
   * @param artifact - Artifact cần kiểm tra
   * @returns Artifact đã được cập nhật
   */
  private static async _checkVerificationStepCompletion(artifact: any): Promise<any> {    
    // Nếu artifact vẫn đang quét, đang trong quá trình verification
    if (artifact.isScanning) {
      return artifact;
    }
    
    // Lấy số lượng và danh sách tickets bằng phương thức tiện ích
    const {
      tickets,
      resolved: resolvedTickets,
      returned: returnedTickets
    } = await ArtifactWorkflowController._getTicketCounts(artifact._id);
    
    // Cập nhật dữ liệu bước verification bằng findOneAndUpdate để tránh xung đột version
    if (artifact.currentWorkflowCycle) {
      // Chuẩn bị dữ liệu verification
      const verificationData: any = {
        'currentWorkflowCycle.verification.numberTicketsResolved': resolvedTickets.length,
        'currentWorkflowCycle.verification.numberTicketsReturnedToProcessing': returnedTickets.length,
        'currentWorkflowCycle.verification.completedAt': new Date()
      };
      
      // Cập nhật bằng findOneAndUpdate để tránh xung đột version
      await ArtifactModel.findByIdAndUpdate(
        artifact._id,
        { $set: verificationData },
        { new: true }
      );
      
      // Lấy dữ liệu artifact mới sau khi cập nhật
      artifact = await ArtifactModel.findById(artifact._id);
    }
    
    // Hoàn thành chu kỳ workflow này và có thể bắt đầu chu kỳ mới
    // Kiểm tra xem có vấn đề nào cần chu kỳ khác không
    if (returnedTickets.length > 0 || artifact.vulnerabilityList?.length > 0) {
      // Lấy artifact mới trước khi bắt đầu chu kỳ mới để đảm bảo có dữ liệu mới nhất
      const freshArtifact = await ArtifactModel.findById(artifact._id);
      if (!freshArtifact) {
        throw new Error(`Failed to retrieve artifact ${artifact._id} before starting new cycle`);
      }
      
      // QUAN TRỌNG: Đầu tiên đảm bảo chu kỳ hiện tại được lưu vào mảng workflowCycles
      if (freshArtifact.currentWorkflowCycle) {
        const currentCycle = freshArtifact.currentWorkflowCycle;
        const cycleNumber = currentCycle.cycleNumber;
        
        // Đánh dấu chu kỳ hiện tại đã hoàn thành
        currentCycle.completedAt = new Date();
        
        // Tìm xem chu kỳ này đã tồn tại trong mảng chưa
        const existingCycleIndex = freshArtifact.workflowCycles?.findIndex(
          (c: any) => c.cycleNumber === cycleNumber
        ) ?? -1;
        
        // Tạo bản sao sạch
        const cycleCopy = JSON.parse(JSON.stringify(currentCycle));
        
        // Hoạt động cập nhật - hoặc cập nhật chu kỳ hiện có hoặc thêm chu kỳ mới
        let updateOp: any;
        
        if (existingCycleIndex >= 0) {
          // Cập nhật chu kỳ hiện có
          updateOp = { 
            $set: { [`workflowCycles.${existingCycleIndex}`]: cycleCopy }
          };
        } else {
          // Thêm chu kỳ mới
          updateOp = { 
            $push: { workflowCycles: cycleCopy }
          };
        }
        
        // Áp dụng cập nhật
        await ArtifactModel.findByIdAndUpdate(
          freshArtifact._id,
          updateOp,
          { new: false }
        );
      }
      
      // Bây giờ khởi tạo chu kỳ workflow mới - sẽ xử lý các cập nhật một cách atomic
      return await ArtifactWorkflowController._initializeWorkflowCycle(freshArtifact._id);
    } else {
      // Cập nhật trạng thái workflow đã hoàn thành - chỉ sử dụng một hoạt động atomic
      const completedArtifact = await ArtifactModel.findByIdAndUpdate(
        artifact._id,
        { $set: { workflowCompleted: true } },
        { new: true }
      );
      
      return completedArtifact;
    }
  }

  /**
   * Lấy số lượng và phân loại tickets của artifact
   * @param artifactId - ID của artifact
   * @returns Object chứa các mảng tickets đã phân loại
   */
  private static async _getTicketCounts(artifactId: string | mongoose.Types.ObjectId): Promise<{
    tickets: any[];
    assigned: any[];
    unassigned: any[];
    submitted: any[];
    notSubmitted: any[];
    resolved: any[];
    returned: any[];
  }> {
    
    // Lấy artifact với threatList đã populate
    const artifact = await ArtifactModel.findById(artifactId).populate('threatList');
    
    if (!artifact || !artifact.threatList) {
      return {
        tickets: [],
        assigned: [],
        unassigned: [],
        submitted: [],
        notSubmitted: [],
        resolved: [],
        returned: []
      };
    }
    
    // Lấy ID của threats
    const threatIds = artifact.threatList.map((threat: any) => threat._id);
    
    // Truy vấn tickets cho các threats này
    const tickets = await TicketModel.find({ 
      targetedThreat: { $in: threatIds }
    });
        
    // Phân loại tickets
    const assigned = tickets.filter((ticket: any) => ticket.status !== "Not accepted");
    const unassigned = tickets.filter((ticket: any) => ticket.status === "Not accepted");
    
    const submitted = tickets.filter((ticket: any) => 
      ticket.status === "Submitted" || ticket.status === "Resolved"
    );
    
    const notSubmitted = tickets.filter((ticket: any) => 
      ticket.status !== "Submitted" && ticket.status !== "Resolved"
    );
    
    const resolved = tickets.filter((ticket: any) => ticket.status === "Resolved");
    
    // Xác định tickets được trả về bằng trường previousStatus
    // Ticket được coi là trả về nếu từng ở trạng thái "Submitted" nhưng giờ quay lại "Processing"
    const returned = tickets.filter((ticket: any) => 
      ticket.status === "Processing" && ticket.previousStatus === "Submitted"
    );
    
    return {
      tickets,
      assigned,
      unassigned,
      submitted,
      notSubmitted,
      resolved,
      returned
    };
  }

  /**
   * Đồng bộ mảng workflow cycles với chu kỳ workflow hiện tại
   * @param artifact - Artifact cần đồng bộ
   */
  private static _syncWorkflowCycles(artifact: any): void {
    if (!artifact.currentWorkflowCycle) {
      return;
    }
    
    if (!artifact.workflowCycles) {
      artifact.workflowCycles = [];
    }
    
    const currentCycleNumber = artifact.currentWorkflowCycle.cycleNumber;
    
    // Tìm chu kỳ tương ứng trong mảng workflowCycles
    const cycleIndex = artifact.workflowCycles.findIndex(
      (cycle: any) => cycle.cycleNumber === currentCycleNumber
    );
    
    // Tạo bản sao sâu để đảm bảo đó là object riêng biệt
    const cycleCopy = JSON.parse(JSON.stringify(artifact.currentWorkflowCycle));
    
    if (cycleIndex === -1) {
      // Thêm nếu không tìm thấy
      artifact.workflowCycles.push(cycleCopy);
    } else {
      // Thay thế chu kỳ hiện có bằng chu kỳ hiện tại để đảm bảo đồng bộ
      artifact.workflowCycles[cycleIndex] = cycleCopy;
    }
    
    // Đảm bảo workflowCyclesCount nhất quán với chu kỳ hiện tại
    if ((artifact.workflowCyclesCount || 0) < currentCycleNumber) {
      artifact.workflowCyclesCount = currentCycleNumber;
    }
  }
  
  /**
   * Xác thực tính nhất quán của workflow
   * @param artifact - Artifact cần xác thực
   */
  private static _validateWorkflowConsistency(artifact: any): void {
    if (!artifact.currentWorkflowCycle) {
      return;
    }
    
    if (!artifact.workflowCycles || artifact.workflowCycles.length === 0) {
      return;
    }
    
    const currentCycleNumber = artifact.currentWorkflowCycle.cycleNumber;
    const matchingCycle = artifact.workflowCycles.find((c: any) => c.cycleNumber === currentCycleNumber);
    
    if (!matchingCycle) {
      // Tự động sửa: thêm chu kỳ hiện tại vào mảng
      const cycleCopy = JSON.parse(JSON.stringify(artifact.currentWorkflowCycle));
      artifact.workflowCycles.push(cycleCopy);
    } else {
      // Xác minh các bước có khớp không
      if (matchingCycle.currentStep !== artifact.currentWorkflowCycle.currentStep) {
        // Tự động sửa: cập nhật chu kỳ trong mảng
        const index = artifact.workflowCycles.findIndex((c: any) => c.cycleNumber === currentCycleNumber);
        if (index !== -1) {
          artifact.workflowCycles[index] = JSON.parse(JSON.stringify(artifact.currentWorkflowCycle));
        }
      }
    }
    
    // Đảm bảo workflowCyclesCount nhất quán
    if (artifact.workflowCyclesCount !== currentCycleNumber) {
      artifact.workflowCyclesCount = currentCycleNumber;
    }
  }
}
