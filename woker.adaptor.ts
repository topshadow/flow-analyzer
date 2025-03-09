// src/core/worker-adapter.ts
export class WorkerEventEmitter extends EventTarget {
    constructor() {
      super();
      
      // 接收主线程消息
      self.onmessage = (e: MessageEvent<{ type: string; data: any }>) => {
        const { type, data } = e.data;
        this.dispatchEvent(new CustomEvent(type, { detail: data }));
      };
    }
  
    /**
     * 向主线程发送事件
     * @param type - 事件类型
     * @param data - 负载数据
     */
    emit<T>(type: string, data?: T) {
      self.postMessage({ type, data });
    }
  }
  