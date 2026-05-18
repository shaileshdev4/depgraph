import { marked } from "marked";

export default function ExecutiveSummary({ markdown }) {
  if (!markdown) return null;
  const html = marked.parse(markdown, { breaks: true });
  return (
    <div
      className="prose prose-invert prose-sm max-w-none text-gray-300"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
