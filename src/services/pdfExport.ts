import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { HealthCheck } from '../data/checks';
import { CATEGORIES } from '../data/checks';

const STATUS_LABEL: Record<string, string> = {
  pass: 'PASS',
  fail: 'FAIL',
  warn: 'WARN',
  info: 'INFO',
  unknown: 'N/A',
};

const STATUS_COLOR: Record<string, [number, number, number]> = {
  pass:    [39, 174, 96],
  fail:    [192, 57, 43],
  warn:    [230, 126, 34],
  info:    [52, 152, 219],
  unknown: [127, 140, 141],
};

export function generatePdf(checks: HealthCheck[], splunkHost: string) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const now = new Date();
  const dateStr = now.toLocaleString('nl-NL', { dateStyle: 'full', timeStyle: 'short' });
  const W = 210;
  const margin = 14;
  const contentW = W - margin * 2;

  // ── Header ────────────────────────────────────────────────────────────────
  doc.setFillColor(30, 35, 50);
  doc.rect(0, 0, W, 30, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.text('Splunk Health Check Report', margin, 13);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(180, 190, 210);
  doc.text(`Host: ${splunkHost}`, margin, 20);
  doc.text(`Gegenereerd: ${dateStr}`, margin, 25);

  // ── Executive Summary ─────────────────────────────────────────────────────
  let y = 38;
  doc.setTextColor(30, 35, 50);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.text('Samenvatting', margin, y);
  y += 6;

  const total   = checks.length;
  const fail    = checks.filter(c => c.status === 'fail').length;
  const warn    = checks.filter(c => c.status === 'warn').length;
  const pass    = checks.filter(c => c.status === 'pass').length;
  const info    = checks.filter(c => c.status === 'info').length;
  const unknown = checks.filter(c => c.status === 'unknown').length;

  const pills = [
    { label: 'Totaal',   value: total,   color: [50, 55, 80] as [number,number,number] },
    { label: 'FAIL',     value: fail,    color: STATUS_COLOR.fail },
    { label: 'WARN',     value: warn,    color: STATUS_COLOR.warn },
    { label: 'PASS',     value: pass,    color: STATUS_COLOR.pass },
    { label: 'INFO',     value: info,    color: STATUS_COLOR.info },
    { label: 'N/A',      value: unknown, color: STATUS_COLOR.unknown },
  ];

  const pillW = contentW / pills.length;
  pills.forEach((pill, i) => {
    const px = margin + i * pillW;
    doc.setFillColor(...pill.color);
    doc.roundedRect(px, y, pillW - 2, 16, 2, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.text(String(pill.value), px + (pillW - 2) / 2, y + 8, { align: 'center' });
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.text(pill.label, px + (pillW - 2) / 2, y + 13, { align: 'center' });
  });

  y += 24;

  // Overall status banner
  const overallStatus = fail > 0 ? 'KRITIEK' : warn > 0 ? 'WAARSCHUWING' : pass === total ? 'GEZOND' : 'ONBEKEND';
  const overallColor = fail > 0 ? STATUS_COLOR.fail : warn > 0 ? STATUS_COLOR.warn : pass === total ? STATUS_COLOR.pass : STATUS_COLOR.unknown;
  doc.setFillColor(...overallColor);
  doc.roundedRect(margin, y, contentW, 10, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text(`Algehele status: ${overallStatus}`, W / 2, y + 7, { align: 'center' });
  y += 18;

  // ── Per category ──────────────────────────────────────────────────────────
  const categories = CATEGORIES.filter(c => c !== 'Overview');

  for (const cat of categories) {
    const catChecks = checks.filter(c => c.category === cat);
    if (catChecks.length === 0) continue;

    if (y > 240) {
      doc.addPage();
      y = 20;
    }

    // Category header
    doc.setFillColor(240, 242, 248);
    doc.rect(margin, y, contentW, 8, 'F');
    doc.setTextColor(30, 35, 50);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.text(cat, margin + 2, y + 5.5);

    const catFail = catChecks.filter(c => c.status === 'fail').length;
    const catWarn = catChecks.filter(c => c.status === 'warn').length;
    const catPass = catChecks.filter(c => c.status === 'pass').length;
    const catUnk  = catChecks.filter(c => c.status === 'unknown').length;
    const catSummary = `${catChecks.length} checks — ${catFail} fail, ${catWarn} warn, ${catPass} pass, ${catUnk} N/A`;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 100, 120);
    doc.text(catSummary, margin + contentW - 2, y + 5.5, { align: 'right' });
    y += 10;

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['#', 'Check', 'Status', 'Bron']],
      body: catChecks.map((c, idx) => [
        String(idx + 1),
        c.title + (c.checkNumber ? ` [${c.checkNumber}]` : ''),
        STATUS_LABEL[c.status],
        c.source === 'monitoring_console' ? 'MC'
          : c.source === 'health_assistant' ? 'HA'
          : c.source === 'smt' ? 'SMT' : 'PS',
      ]),
      columnStyles: {
        0: { cellWidth: 8, halign: 'center', fontSize: 7 },
        1: { cellWidth: contentW - 8 - 20 - 14, fontSize: 8 },
        2: { cellWidth: 20, halign: 'center', fontSize: 8, fontStyle: 'bold' },
        3: { cellWidth: 14, halign: 'center', fontSize: 7 },
      },
      headStyles: {
        fillColor: [50, 55, 80],
        textColor: [255, 255, 255],
        fontStyle: 'bold',
        fontSize: 8,
      },
      bodyStyles: { fontSize: 8, cellPadding: 2 },
      didParseCell(data) {
        if (data.section === 'body' && data.column.index === 2) {
          const status = catChecks[data.row.index]?.status ?? 'unknown';
          const [r, g, b] = STATUS_COLOR[status] ?? STATUS_COLOR.unknown;
          data.cell.styles.textColor = [r, g, b];
        }
      },
      alternateRowStyles: { fillColor: [248, 249, 252] },
    });

    y = (doc as any).lastAutoTable.finalY + 6;
  }

  // ── Failed & Warning details ──────────────────────────────────────────────
  const issues = checks.filter(c => c.status === 'fail' || c.status === 'warn');
  if (issues.length > 0) {
    doc.addPage();
    let dy = 20;

    doc.setTextColor(30, 35, 50);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.text('Details — Fails & Warnings', margin, dy);
    dy += 8;

    for (const check of issues) {
      if (dy > 250) { doc.addPage(); dy = 20; }

      const [r, g, b] = STATUS_COLOR[check.status];
      doc.setFillColor(r, g, b);
      doc.rect(margin, dy, 3, 12, 'F');

      doc.setTextColor(30, 35, 50);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.text(check.title, margin + 6, dy + 5);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(80, 85, 100);
      const wrapped = doc.splitTextToSize(check.suggestedAction, contentW - 10);
      doc.text(wrapped, margin + 6, dy + 10);

      dy += 8 + wrapped.length * 4 + 4;
    }
  }

  // ── Footer on all pages ────────────────────────────────────────────────────
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(160, 160, 170);
    doc.setFont('helvetica', 'normal');
    doc.text(`Splunk Health Check — ${dateStr} — pagina ${i} van ${pageCount}`, W / 2, 292, { align: 'center' });
  }

  doc.save(`splunk-health-check-${now.toISOString().slice(0, 10)}.pdf`);
}
