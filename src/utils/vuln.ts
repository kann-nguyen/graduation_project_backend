import axios from "axios";
import { ArtifactModel, ProjectModel } from "../models/models";
import getOctokit, { createOctokitClient } from "../octokit";
import { Result } from "./vulnType";
import { Gitlab } from "@gitbeaker/rest";
import { Types } from "mongoose";
import { safeGithubClient, safeGitlabClient } from "./token";

// Chuyển đổi dữ liệu từ API NVD thành định dạng dễ sử dụng
function resolveData(data: Result) {
  if (data.totalResults === 0) return []; // Trả về mảng rỗng nếu không có lỗ hổng nào
  return data.vulnerabilities.map((v) => {
    const cveId = v.cve.id; // Lấy mã định danh CVE
    const description = v.cve.descriptions[0].value; // Lấy mô tả lỗ hổng
    const score = v.cve.metrics.cvssMetricV2[0].cvssData.baseScore; // Lấy điểm số CVSS
    const severity = v.cve.metrics.cvssMetricV2[0].baseSeverity; // Lấy mức độ nghiêm trọng
    const cwes = v.cve.weaknesses.map((w) => w.description[0].value); // Lấy danh sách CWE liên quan

    return {
      cveId,
      description,
      score,
      severity,
      cwes,
    };
  });
}

// Hàm lấy danh sách lỗ hổng từ NVD dựa trên CPE (Common Platform Enumeration)
export async function fetchVulnsFromNVD(cpe: string) {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${cpe}`; // API của NVD
  try {
    const { data } = await axios.get<Result>(url);
    return resolveData(data); // Xử lý dữ liệu và trả về danh sách lỗ hổng
  } catch (error) {
    return []; // Trả về mảng rỗng nếu có lỗi xảy ra
  }
}

// Định nghĩa kiểu dữ liệu cho rule trong kết quả quét bảo mật
interface OverrideType {
  id?: string | null | undefined;
  name?: string | undefined;
  tags?: string[] | null | undefined;
  severity?: "none" | "note" | "warning" | "error" | null | undefined;
  description?: string | undefined;
  security_severity_level?: string | undefined;
}

// Hàm nhập kết quả quét bảo mật từ GitHub
export async function importGithubScanResult(
  accountId: Types.ObjectId | undefined,
  url: string
) {
  const [owner, repo] = url.split("/").slice(-2); // Tách lấy owner và repo từ URL
  const octokit = await safeGithubClient(accountId); // Lấy client GitHub an toàn
  try {
    const { data } = await octokit.rest.codeScanning.listAlertsForRepo({
      owner,
      repo,
    }); // Gọi API GitHub để lấy danh sách cảnh báo bảo mật

    const vulns = data.map((v: { rule?: OverrideType; most_recent_instance?: any; }) => {
      const {
        rule: { id, description, tags, security_severity_level: severity },
      } = v as {
        rule: OverrideType;
      };
      const {
        most_recent_instance: { location },
      } = v;
      
      // Trích xuất danh sách CWE từ tags
      const cweList = tags
        ?.map((x) => {
          const regex = /external\/cwe\/cwe-\d+/;
          if (regex.test(x)) return x.split("/")[2].toUpperCase();
          return null;
        })
        .filter((x) => x !== null);
      
      // Tạo mô tả chi tiết từ thông báo và vị trí của lỗ hổng
      const desc = `${description}. Found at ${location?.path} from line ${location?.start_line} to ${location?.end_line}`;
      return {
        cveId: id,
        description: desc,
        severity,
        cwes: cweList,
      };
    });
    
    // Cập nhật danh sách lỗ hổng vào database
    await ArtifactModel.updateOne(
      { url },
      {
        $set: {
          vulnerabilityList: vulns,
        },
      }
    );
    return true;
  } catch (error) {
    console.log(error);
    return false; // Trả về false nếu có lỗi xảy ra
  }
}

// Hàm nhập kết quả quét bảo mật từ GitLab
export async function importGitlabScanResult(
  accountId: Types.ObjectId | undefined,
  url: string
) {
  // const api = await safeGitlabClient(accountId); // Lấy client GitLab an toàn
  // try {
  //   const project = await ProjectModel.findOne({ url }); // Tìm dự án trong database
  //   if (!project) return false; // Nếu không tìm thấy, trả về false
    
  //   const projectId = encodeURIComponent(project.name); // Mã hóa tên dự án để dùng trong API
  //   const data = await api.ProjectVulnerabilities.all(projectId); // Lấy danh sách lỗ hổng từ GitLab
    
  //   const vulns = data.map((v) => ({
  //     cveId: v.id,
  //     description: v.description,
  //     severity: v.severity,
  //     cwes: [],
  //   }));
    
  //   // Cập nhật danh sách lỗ hổng vào database
  //   await ArtifactModel.updateOne(
  //     {
  //       url,
  //     },
  //     {
  //       $set: {
  //         vulnerabilityList: vulns,
  //       },
  //     }
  //   );
  //   return true;
  // } catch (error) {
  //   console.log(error);
  //   return false; // Trả về false nếu có lỗi xảy ra
  // }
}
