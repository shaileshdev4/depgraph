import { marked } from "marked";

export default function ExecutiveSummary({ markdown }) {
  if (!markdown) {
    return (
      <p className="text-sm text-gray-500">
        Executive summary will appear after investigation completes.
      </p>
    );
  }
  const html = marked.parse(markdown, { breaks: true });
  return (
    <div
      className="prose prose-invert prose-sm max-w-none text-gray-300 overflow-y-auto h-full"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
