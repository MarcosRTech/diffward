import DOMPurify from "dompurify";

export function Comment({ html }: { html: string }) {
  return (
    <div>
      {/* ruleid: js/xss */}
      <div dangerouslySetInnerHTML={{ __html: html }} />
      {/* ok: js/xss */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
      {/* ok: js/xss */}
      <div dangerouslySetInnerHTML={{ __html: "<hr/>" }} />
    </div>
  );
}
