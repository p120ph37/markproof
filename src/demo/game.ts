/**
 * Dino Runner — a Chrome Dino-style endless runner game.
 * This is the demo app for the markproof trust-anchored web app loader.
 */

const CANVAS_W = 800;
const CANVAS_H = 250;
const GROUND_Y = 200;
const DINO_W = 40;
const DINO_H = 44;
const GRAVITY = 0.7;
const JUMP_VEL = -13;
const INIT_SPEED = 5;
const MAX_SPEED = 14;
const ACCEL = 0.001;
const CACTUS_MIN_GAP = 80;

interface Obstacle {
  x: number;
  w: number;
  h: number;
  type: 'small' | 'tall' | 'double';
}

interface Cloud {
  x: number;
  y: number;
}

interface Dino {
  x: number;
  y: number;
  vy: number;
  ducking: boolean;
}

let canvas: HTMLCanvasElement;
let ctx: CanvasRenderingContext2D;
let dino: Dino;
let obstacles: Obstacle[];
let clouds: Cloud[];
let score: number;
let highScore: number;
let speed: number;
let gameOver: boolean;
let started: boolean;
let groundOffset: number;
let frameCount: number;

function init() {
  // Find or create canvas
  canvas = document.getElementById('game-canvas') as HTMLCanvasElement;
  if (!canvas) {
    canvas = document.createElement('canvas');
    canvas.id = 'game-canvas';
    document.body.appendChild(canvas);
  }
  canvas.width = CANVAS_W;
  canvas.height = CANVAS_H;
  canvas.style.display = 'block';
  canvas.style.margin = '0 auto';
  canvas.style.background = '#f7f7f7';
  canvas.style.borderRadius = '4px';
  canvas.style.imageRendering = 'pixelated';

  ctx = canvas.getContext('2d')!;

  highScore = parseInt(localStorage.getItem('dino-hi') || '0', 10);

  reset();

  // Input
  const onAction = (e: Event) => {
    e.preventDefault();
    if (gameOver) { reset(); return; }
    if (!started) { started = true; }
    if (dino.y >= GROUND_Y - DINO_H) {
      dino.vy = JUMP_VEL;
    }
  };

  const onDuck = (down: boolean) => {
    if (!gameOver && started) dino.ducking = down;
  };

  document.addEventListener('keydown', (e) => {
    if (e.code === 'Space' || e.code === 'ArrowUp') onAction(e);
    if (e.code === 'ArrowDown') onDuck(true);
  });
  document.addEventListener('keyup', (e) => {
    if (e.code === 'ArrowDown') onDuck(false);
  });
  canvas.addEventListener('touchstart', onAction);
  canvas.addEventListener('click', onAction);

  // Start render loop
  requestAnimationFrame(loop);
}

function reset() {
  dino = { x: 60, y: GROUND_Y - DINO_H, vy: 0, ducking: false };
  obstacles = [];
  clouds = [
    { x: 200, y: 40 },
    { x: 450, y: 60 },
    { x: 700, y: 30 },
  ];
  score = 0;
  speed = INIT_SPEED;
  gameOver = false;
  started = false;
  groundOffset = 0;
  frameCount = 0;
}

function spawnObstacle() {
  const lastX = obstacles.length > 0 ? obstacles[obstacles.length - 1].x : 0;
  if (lastX > CANVAS_W - CACTUS_MIN_GAP / speed * INIT_SPEED) return;

  const r = Math.random();
  let type: Obstacle['type'];
  let w: number, h: number;
  if (r < 0.4) {
    type = 'small'; w = 16; h = 30;
  } else if (r < 0.75) {
    type = 'tall'; w = 16; h = 46;
  } else {
    type = 'double'; w = 30; h = 30;
  }

  obstacles.push({ x: CANVAS_W + 20, w, h, type });
}

function update() {
  if (!started || gameOver) return;

  frameCount++;
  speed = Math.min(MAX_SPEED, INIT_SPEED + frameCount * ACCEL);
  score = Math.floor(frameCount / 6);

  // Dino physics
  const dinoH = dino.ducking ? DINO_H * 0.6 : DINO_H;
  dino.vy += GRAVITY;
  dino.y += dino.vy;
  if (dino.y >= GROUND_Y - dinoH) {
    dino.y = GROUND_Y - dinoH;
    dino.vy = 0;
  }

  // Ground scroll
  groundOffset = (groundOffset + speed) % 24;

  // Obstacles
  if (frameCount % Math.max(30, Math.floor(90 - speed * 3)) === 0) {
    spawnObstacle();
  }

  for (let i = obstacles.length - 1; i >= 0; i--) {
    obstacles[i].x -= speed;
    if (obstacles[i].x < -50) {
      obstacles.splice(i, 1);
      continue;
    }

    // Collision
    const o = obstacles[i];
    const dx = dino.x;
    const dy = dino.y;
    const dw = DINO_W - 8; // hitbox padding
    const dh = dinoH - 4;
    const ox = o.x + 2;
    const oy = GROUND_Y - o.h;

    if (dx + dw > ox && dx < ox + o.w - 2 &&
        dy + dh > oy && dy < oy + o.h) {
      gameOver = true;
      if (score > highScore) {
        highScore = score;
        localStorage.setItem('dino-hi', String(highScore));
      }
    }
  }

  // Clouds
  for (const c of clouds) {
    c.x -= speed * 0.3;
    if (c.x < -60) {
      c.x = CANVAS_W + 40;
      c.y = 20 + Math.random() * 60;
    }
  }
}

// ===================== Drawing =====================

function drawDino() {
  const dinoH = dino.ducking ? DINO_H * 0.6 : DINO_H;
  const x = Math.floor(dino.x);
  const y = Math.floor(dino.y);

  ctx.fillStyle = '#535353';

  if (dino.ducking) {
    // Ducking dino: wider and shorter
    ctx.fillRect(x, y + 4, 44, dinoH - 4);
    ctx.fillRect(x + 36, y, 12, 10);
    // Eye
    ctx.fillStyle = '#f7f7f7';
    ctx.fillRect(x + 42, y + 2, 4, 4);
    // Legs
    ctx.fillStyle = '#535353';
    const legFrame = Math.floor(frameCount / 4) % 2;
    ctx.fillRect(x + 6 + legFrame * 14, y + dinoH - 2, 6, 6);
    ctx.fillRect(x + 20 - legFrame * 14, y + dinoH - 2, 6, 6);
  } else {
    // Standing dino: T-Rex silhouette
    // Head
    ctx.fillRect(x + 18, y, 22, 16);
    // Eye (white space)
    ctx.fillStyle = '#f7f7f7';
    ctx.fillRect(x + 32, y + 4, 4, 4);
    ctx.fillStyle = '#535353';
    // Jaw
    ctx.fillRect(x + 24, y + 14, 16, 6);
    // Neck
    ctx.fillRect(x + 16, y + 12, 12, 8);
    // Body
    ctx.fillRect(x + 4, y + 16, 28, 18);
    // Arm
    ctx.fillRect(x + 28, y + 22, 6, 8);
    // Tail
    ctx.fillRect(x, y + 18, 8, 8);
    // Legs (animated)
    if (started && !gameOver) {
      const legFrame = Math.floor(frameCount / 4) % 2;
      ctx.fillRect(x + 8 + legFrame * 10, y + 34, 6, 10);
      ctx.fillRect(x + 18 - legFrame * 10, y + 34, 6, 10);
    } else {
      ctx.fillRect(x + 8, y + 34, 6, 10);
      ctx.fillRect(x + 20, y + 34, 6, 10);
    }
  }
}

function drawCactus(o: Obstacle) {
  ctx.fillStyle = '#2d5a27';
  const x = Math.floor(o.x);
  const y = GROUND_Y - o.h;

  if (o.type === 'small') {
    ctx.fillRect(x + 4, y, 8, o.h);
    ctx.fillRect(x, y + 8, 4, 12);
    ctx.fillRect(x + 12, y + 14, 4, 10);
  } else if (o.type === 'tall') {
    ctx.fillRect(x + 4, y, 8, o.h);
    ctx.fillRect(x, y + 6, 4, 16);
    ctx.fillRect(x + 12, y + 12, 4, 14);
    ctx.fillRect(x, y + 4, 2, 4);
    ctx.fillRect(x + 14, y + 10, 2, 4);
  } else {
    // Double cactus
    ctx.fillRect(x + 2, y + 4, 8, o.h - 4);
    ctx.fillRect(x + 18, y, 8, o.h);
    ctx.fillRect(x, y + 12, 4, 8);
    ctx.fillRect(x + 26, y + 8, 4, 10);
  }
}

function drawCloud(c: Cloud) {
  ctx.fillStyle = '#e0e0e0';
  const x = Math.floor(c.x);
  const y = Math.floor(c.y);
  ctx.fillRect(x + 6, y, 34, 10);
  ctx.fillRect(x, y + 4, 46, 8);
  ctx.fillRect(x + 4, y + 10, 38, 4);
}

function drawGround() {
  ctx.fillStyle = '#535353';
  ctx.fillRect(0, GROUND_Y, CANVAS_W, 1);

  // Ground texture
  ctx.fillStyle = '#999';
  for (let x = -groundOffset; x < CANVAS_W; x += 24) {
    ctx.fillRect(x, GROUND_Y + 4, 12, 1);
    ctx.fillRect(x + 8, GROUND_Y + 8, 6, 1);
  }
}

function drawScore() {
  ctx.fillStyle = '#535353';
  ctx.font = '16px monospace';
  ctx.textAlign = 'right';

  const scoreStr = String(score).padStart(5, '0');
  ctx.fillText(scoreStr, CANVAS_W - 20, 30);

  if (highScore > 0) {
    ctx.fillStyle = '#999';
    ctx.fillText('HI ' + String(highScore).padStart(5, '0') + '  ', CANVAS_W - 80, 30);
  }
}

function drawStartScreen() {
  ctx.fillStyle = '#535353';
  ctx.font = '18px monospace';
  ctx.textAlign = 'center';
  ctx.fillText('Press SPACE or tap to start', CANVAS_W / 2, CANVAS_H / 2 - 20);
  ctx.font = '12px monospace';
  ctx.fillStyle = '#999';
  ctx.fillText('Dino Runner — markproof Demo', CANVAS_W / 2, CANVAS_H / 2 + 10);
}

function drawGameOver() {
  ctx.fillStyle = '#535353';
  ctx.font = 'bold 20px monospace';
  ctx.textAlign = 'center';
  ctx.fillText('GAME OVER', CANVAS_W / 2, CANVAS_H / 2 - 20);
  ctx.font = '14px monospace';
  ctx.fillText('Press SPACE or tap to restart', CANVAS_W / 2, CANVAS_H / 2 + 10);
}

function render() {
  ctx.clearRect(0, 0, CANVAS_W, CANVAS_H);

  // Clouds (always draw)
  for (const c of clouds) drawCloud(c);

  // Ground
  drawGround();

  // Obstacles
  for (const o of obstacles) drawCactus(o);

  // Dino
  drawDino();

  // Score
  if (started) drawScore();

  // Overlays
  if (!started && !gameOver) drawStartScreen();
  if (gameOver) drawGameOver();
}

function loop() {
  update();
  render();
  requestAnimationFrame(loop);
}

// Boot
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
