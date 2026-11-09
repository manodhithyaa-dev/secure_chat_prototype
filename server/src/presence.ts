import type { Socket } from 'socket.io';

const socketsByUser = new Map<string, Set<Socket>>();

export const presence = {
  add(userId: string, socket: Socket): void {
    let set = socketsByUser.get(userId);
    if (!set) {
      set = new Set();
      socketsByUser.set(userId, set);
    }
    set.add(socket);
  },

  remove(userId: string, socket: Socket): void {
    const set = socketsByUser.get(userId);
    if (!set) return;
    set.delete(socket);
    if (set.size === 0) socketsByUser.delete(userId);
  },

  isOnline(userId: string): boolean {
    return (socketsByUser.get(userId)?.size ?? 0) > 0;
  },

  socketsFor(userId: string): Socket[] {
    return Array.from(socketsByUser.get(userId) ?? []);
  }
};
