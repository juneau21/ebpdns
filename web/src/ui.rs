//! 共享 UI 微件（动画 / 可访问性）：只做 class 切换，不引入任何新依赖。
//!
//! 设计约束（v2.1.7 动画要求「克制且不卡顿」）：
//! - 只用 CSS `transition` / `@keyframes`，不动 layout 属性（不改 width/height/top/left），
//!   动画属性限定 `opacity` / `background-color` / `color` / `box-shadow`，避免逐帧重排；
//! - 尊重 `prefers-reduced-motion: reduce`（CSS 侧统一关闭，见 style.css）；
//! - 数值变化高亮用「交替两个等价 keyframes 名」实现重放：class 从 a 切到 b 时
//!   `animation-name` 变化 → 动画重新开始，无需 JS 定时器，也没有每帧回调。
use leptos::prelude::*;

/// 数值变化高亮：文本内容变化时重放一次 300ms 高亮（首次渲染不闪）。
pub fn live_span(id: &'static str, cls: &'static str, f: impl Fn() -> String + 'static) -> AnyView {
    live_span_unit(id, cls, "", f)
}

/// 同上，额外在尾部渲染一个 `.u` 单位小字（如 `ms` / `%`）。
pub fn live_span_unit(
    id: &'static str,
    cls: &'static str,
    unit: &'static str,
    f: impl Fn() -> String + 'static,
) -> AnyView {
    let shown = RwSignal::new(String::new());
    let gen = RwSignal::new(0u32);
    Effect::new(move |_: Option<()>| {
        let t = f();
        let prev = shown.get_untracked();
        if prev == t {
            return;
        }
        // 首次赋值不触发高亮（避免首屏所有数字一起闪）。
        let first = prev.is_empty();
        shown.set(t);
        if !first {
            gen.update(|g| *g = g.wrapping_add(1));
        }
    });
    view! {
        <span
            class=cls
            id=id
            class:lv-flash-a=move || gen.get().is_multiple_of(2)
            class:lv-flash-b=move || gen.get() % 2 == 1
        >
            {move || shown.get()}
            <span class="u">{unit}</span>
        </span>
    }
    .into_any()
}
