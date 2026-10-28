/**
 * CSV export for the admin panel.
 *
 * Cells that begin with a spreadsheet formula trigger are prefixed with an
 * apostrophe so an exported note cannot execute when the file is opened.
 */

const FORMULA = /^[=+\-@\t\r]/;

function cell(value) {
  if (value === null || value === undefined) return "";
  let text = String(value);
  if (FORMULA.test(text)) text = `'${text}`;
  if (/[",\n\r]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
  return text;
}

export function toCsv(rows, columns) {
  const header = columns.map((column) => cell(column.label)).join(",");
  const lines = rows.map((row) => columns.map((column) => cell(row[column.key])).join(","));
  return [header, ...lines].join("\n");
}
