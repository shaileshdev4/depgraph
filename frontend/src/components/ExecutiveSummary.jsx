import { marked } from "marked";

marked.setOptions({
  gfm: true,
  breaks: true,
  headerIds: false,
  mangle: false,
});

function normalizeSummaryMarkdown(raw) {
  if (!raw) return "";
  let text = String(raw).trim();
  if (text.includes("\\n")) {
    text = text.replace(/\\n/g, "\n");
  }
  const fenced = text.match(/^```(?:markdown|md)?\s*([\s\S]*?)```$/i);
  if (fenced) {
    text = fenced[1].trim();
  }
  return text;
}

export default function ExecutiveSummary({ markdown }) {
  const normalized = normalizeSummaryMarkdown(markdown);
  if (!normalized) return null;
  const html = marked.parse(normalized);
  return (
    <div
      className="depgraph-summary-prose prose prose-invert prose-sm max-w-none"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
