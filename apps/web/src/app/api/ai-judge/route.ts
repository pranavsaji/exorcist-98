import { handleAiJudgeGet, handleAiJudgePost } from '@/lib/ai-judge-handler';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

/** The AI judge for Bring Your Own Attack; off unless the operator turns it on (lib/ai-judge.ts). */
export const GET = handleAiJudgeGet;
export const POST = (request: Request): Promise<Response> => handleAiJudgePost(request);
