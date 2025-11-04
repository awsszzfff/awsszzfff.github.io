import { defineCollection, z } from "astro:content";

const postsCollection = defineCollection({
	schema: z.object({
		title: z.string(),
		published: z.date().optional(),
		date: z.date().optional(), // 支持用户的date字段
		updated: z.date().optional(),
		draft: z.boolean().optional().default(false),
		description: z.string().optional().default(""),
		image: z.string().optional().default(""),
		tags: z.array(z.string()).optional().default([]),
		category: z.string().optional().nullable().default(""), // 保持向后兼容
		categories: z.array(z.string()).optional().default([]), // 支持用户的categories字段
		lang: z.string().optional().default(""),

		/* For internal use */
		prevTitle: z.string().default(""),
		prevSlug: z.string().default(""),
		nextTitle: z.string().default(""),
		nextSlug: z.string().default(""),
	}).transform((data) => {
		// 如果没有published但有date，使用date作为published
		if (!data.published && data.date) {
			data.published = data.date;
		}
		// 如果没有published也没有date，使用当前日期
		if (!data.published) {
			data.published = new Date();
		}
		return data;
	}),
});
const specCollection = defineCollection({
	schema: z.object({}),
});
export const collections = {
	posts: postsCollection,
	spec: specCollection,
};
