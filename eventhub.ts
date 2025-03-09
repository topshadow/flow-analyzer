// src/core/worker-manager.ts
export class WorkerEventBridge extends EventTarget {
    private workers = new Map<string, Worker>();
    
    /**
     * 创建 Worker 通道
     * @param workerId - Worker唯一标识
     * @param scriptPath - Worker脚本路径
     * @param permissions - Deno权限配置
     */
    async createWorker(
      workerId: string,
      scriptPath: string,
      permissions: Deno.PermissionOptions = { 
        net: true,
        read: true 
      }
    ): Promise<void> {
      const worker = new Worker(new URL(scriptPath, import.meta.url).href, {
        type: "module",
        deno: { permissions }
      });
  
      // 消息转发为事件
      worker.onmessage = (e: MessageEvent) => {
        const { type, data } = e.data;
        this.dispatchEvent(new CustomEvent(type, { detail: data }));
      };
  
      // 错误处理
      worker.onerror = (e: ErrorEvent) => {
        this.dispatchEvent(new CustomEvent("error", { 
          detail: { 
            workerId,
            error: e.error 
          }
        }));
      };
  
      this.workers.set(workerId, worker);
    }
  
    /**
     * 向 Worker 发送指令
     * @param workerId - 目标 Worker ID
     * @param type - 事件类型
     * @param data - 负载数据
     */
    sendCommand<T>(workerId: string, type: string, data?: string) {
      const worker = this.workers.get(workerId);
      if (!worker) throw new Error(`Worker ${workerId} 未找到`);
      worker.postMessage({ type, data });
    }
  
    /**
     * 终止 Worker
     * @param workerId - 目标 Worker ID
     */
    terminateWorker(workerId: string) {
      const worker = this.workers.get(workerId);
      worker?.terminate();
      this.workers.delete(workerId);
    }
  }
  